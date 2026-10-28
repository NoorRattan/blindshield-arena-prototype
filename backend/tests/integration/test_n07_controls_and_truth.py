"""Synthetic component routing, canary workflow and durable scoring/budget truth.

These fixtures exercise actual lane/controller/queue code with synthetic models,
temporary SQLite stores and a synthetic processing observer. They do not prove
real model context/KV isolation, Docker confinement or public-corpus admission.
"""

import asyncio
from contextlib import closing
import json
from types import SimpleNamespace
from typing import List
from uuid import uuid4

import pytest

from arena.adapters.llama_adapter import LlamaModelAdapter
from arena.contracts.api import DefenseDecision, EpochRequest, TargetRequest, TargetResponse, TurnSubmission
from arena.contracts.common import Context
from arena.evaluation.rubric import evaluate_refusal_rubric, validate_defense_symbol_channel
from arena.integration.lanes import ThreeLaneModel
from arena.ports import DependencyUnavailable, TargetNotDispatched
from test_n04 import environment as n04_environment, payload, turn, verify_export
from test_n06_execution import environment as n06_environment, submit


def create_context(epoch: int = 1) -> Context:
    return Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=epoch)


class MockCellModel:
    def __init__(self, name: str = "mock"):
        self.name = name
        self.calls: List[TargetRequest] = []
        self.failure: BaseException | None = None
        self.resets: List[str] = []
        self.in_flight = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()

    async def infer(self, req: TargetRequest) -> TargetResponse:
        self.calls.append(req)
        self.in_flight.set()
        await self.release.wait()
        if self.failure:
            raise self.failure
        identity = {name: getattr(req, name) for name in (
            "domain_id", "experiment_id", "epoch", "attempt_id", "session_id", "turn_index"
        )}
        return TargetResponse(**identity, text=req.text, input_tokens=1, output_tokens=1, duration_us=1)

    async def reset(self, session_id: str) -> None:
        self.resets.append(session_id)
        if self.failure:
            raise self.failure


def build_three_lane_pool():
    cells = [SimpleNamespace(container=f"cell-{i}", model=MockCellModel(f"model-{i}")) for i in range(3)]
    recreated_lanes: List[int] = []

    def recreate(lane: int):
        recreated_lanes.append(lane)
        return SimpleNamespace(container=f"cell-{lane}-recreated-{len(recreated_lanes)}", model=MockCellModel(f"model-{lane}-new"))

    model = ThreeLaneModel(cells, recreate)
    return model, cells, recreated_lanes


# ===========================================================================
# Section 1: MN07-05 Synthetic Routing, Canary Workflow, and Reset Refusal
# ===========================================================================

def test_lane_sticky_continuity_and_cross_session_separation():
    """Multi-turn requests within the same session maintain sticky lane assignment."""
    model, cells, _ = build_three_lane_pool()
    ctx = create_context()
    s1, s2 = str(uuid4()), str(uuid4())

    model.bind_session(s1, 0, ctx)
    model.bind_session(s2, 1, ctx)

    assert model.get_assigned_lane(s1) == "lane-0"
    assert model.get_assigned_lane(s2) == "lane-1"

    # Turn 0 in s1
    req1_t0 = TargetRequest(**ctx.model_dump(), session_id=s1, attempt_id=str(uuid4()), turn_index=0, text="t0", max_output_tokens=16)
    resp1_t0 = asyncio.run(model.infer(req1_t0))
    assert resp1_t0.text == "t0"
    assert len(cells[0].model.calls) == 1
    assert len(cells[1].model.calls) == 0

    # Turn 1 in s1 stays in lane 0
    req1_t1 = TargetRequest(**ctx.model_dump(), session_id=s1, attempt_id=str(uuid4()), turn_index=1, text="t1", max_output_tokens=16)
    resp1_t1 = asyncio.run(model.infer(req1_t1))
    assert len(cells[0].model.calls) == 2
    assert len(cells[1].model.calls) == 0

    # Turn in s2 goes to lane 1
    req2_t0 = TargetRequest(**ctx.model_dump(), session_id=s2, attempt_id=str(uuid4()), turn_index=0, text="s2_t0", max_output_tokens=16)
    resp2_t0 = asyncio.run(model.infer(req2_t0))
    assert len(cells[1].model.calls) == 1
    assert len(cells[0].model.calls) == 2


def test_cross_domain_or_epoch_mismatch_refuses_dispatch():
    """Attempting inference with mismatched context (domain, experiment, or epoch) refuses dispatch."""
    model, _, _ = build_three_lane_pool()
    ctx = create_context(epoch=1)
    session_id = str(uuid4())
    model.bind_session(session_id, 0, ctx)

    # Wrong epoch
    wrong_epoch_ctx = Context(domain_id=ctx.domain_id, experiment_id=ctx.experiment_id, epoch=2)
    req_bad_epoch = TargetRequest(**wrong_epoch_ctx.model_dump(), session_id=session_id, attempt_id=str(uuid4()), turn_index=0, text="hi", max_output_tokens=16)
    with pytest.raises(TargetNotDispatched, match="MODEL_BROKER_BINDING_REQUIRED"):
        asyncio.run(model.infer(req_bad_epoch))

    # Wrong domain
    wrong_domain_ctx = Context(domain_id=str(uuid4()), experiment_id=ctx.experiment_id, epoch=1)
    req_bad_domain = TargetRequest(**wrong_domain_ctx.model_dump(), session_id=session_id, attempt_id=str(uuid4()), turn_index=0, text="hi", max_output_tokens=16)
    with pytest.raises(TargetNotDispatched, match="MODEL_BROKER_BINDING_REQUIRED"):
        asyncio.run(model.infer(req_bad_domain))


def test_unexpected_inference_exception_quarantines_lane_with_zero_retry():
    """An unexpected model exception marks execution UNKNOWN, quarantines the lane, and never retries."""
    model, cells, _ = build_three_lane_pool()
    ctx = create_context()
    session_id = str(uuid4())
    model.bind_session(session_id, 0, ctx)

    cells[0].model.failure = RuntimeError("unexpected process abort")
    req = TargetRequest(**ctx.model_dump(), session_id=session_id, attempt_id=str(uuid4()), turn_index=0, text="fail", max_output_tokens=16)

    with pytest.raises(RuntimeError, match="unexpected process abort"):
        asyncio.run(model.infer(req))

    assert 0 in model.quarantined
    assert len(model.trace) == 1
    assert model.trace[0]["execution"] == "UNKNOWN"

    # Subsequent turn on the same lane is rejected with TargetNotDispatched("MODEL_LANE_QUARANTINED")
    cells[0].model.failure = None
    req_retry = TargetRequest(**ctx.model_dump(), session_id=session_id, attempt_id=str(uuid4()), turn_index=1, text="retry", max_output_tokens=16)
    with pytest.raises(TargetNotDispatched, match="MODEL_LANE_QUARANTINED"):
        asyncio.run(model.infer(req_retry))

    # Lane 0 calls remained exactly 1 (no silent hidden retry)
    assert len(cells[0].model.calls) == 1


def test_cancelled_infer_quarantines_lane_without_hidden_redispatch():
    """Cancelling an in-flight infer call marks execution UNKNOWN and quarantines the lane."""
    async def scenario():
        model, cells, _ = build_three_lane_pool()
        ctx = create_context()
        session_id = str(uuid4())
        model.bind_session(session_id, 1, ctx)

        cells[1].model.release.clear()  # Block in infer
        req = TargetRequest(**ctx.model_dump(), session_id=session_id, attempt_id=str(uuid4()), turn_index=0, text="block", max_output_tokens=16)

        task = asyncio.create_task(model.infer(req))
        await asyncio.wait_for(cells[1].model.in_flight.wait(), 1)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert 1 in model.quarantined
        assert model.trace[0]["execution"] == "UNKNOWN"
        assert len(cells[1].model.calls) == 1
        with pytest.raises(TargetNotDispatched, match="MODEL_LANE_QUARANTINED"):
            await model.infer(req)
        assert len(cells[1].model.calls) == 1

    asyncio.run(scenario())


def test_reset_refusal_on_active_and_quarantined_lanes():
    """ThreeLaneModel.reset strictly refuses active or quarantined lanes."""
    async def scenario():
        model, cells, _ = build_three_lane_pool()
        ctx = create_context()
        s_active, s_quarantine = str(uuid4()), str(uuid4())

        model.bind_session(s_active, 0, ctx)
        model.bind_session(s_quarantine, 1, ctx)

        # 1. Refuse reset while lane is active
        cells[0].model.release.clear()
        req = TargetRequest(**ctx.model_dump(), session_id=s_active, attempt_id=str(uuid4()), turn_index=0, text="hang", max_output_tokens=16)
        infer_task = asyncio.create_task(model.infer(req))
        await asyncio.wait_for(cells[0].model.in_flight.wait(), 1)

        with pytest.raises(DependencyUnavailable, match="LANE_NOT_SAFE_TO_RESET"):
            await model.reset(s_active)

        cells[0].model.release.set()
        await infer_task

        # 2. Refuse reset when lane is quarantined
        cells[1].model.failure = RuntimeError("fault")
        req_q = TargetRequest(**ctx.model_dump(), session_id=s_quarantine, attempt_id=str(uuid4()), turn_index=0, text="crash", max_output_tokens=16)
        with pytest.raises(RuntimeError):
            await model.infer(req_q)
        assert 1 in model.quarantined

        with pytest.raises(DependencyUnavailable, match="LANE_NOT_SAFE_TO_RESET"):
            await model.reset(s_quarantine)

    asyncio.run(scenario())


def test_canary_recall_failure_reports_inconclusive_never_fabricated_success(monkeypatch):
    """Run the canary/reset workflow with synthetic models that cannot recall markers."""
    from arena.integration.lane_checks import check_lane_state

    async def scenario():
        cells = [SimpleNamespace(container=f"synthetic-{i}",
                 model=LlamaModelAdapter(synthetic_mode=True, max_lanes=1)) for i in range(3)]
        recreated = []

        def recreate(lane):
            recreated.append(lane)
            return SimpleNamespace(container=f"synthetic-recreated-{len(recreated)}",
                                   model=LlamaModelAdapter(synthetic_mode=True, max_lanes=1))

        runtime = SimpleNamespace(cells=cells, model=ThreeLaneModel(cells, recreate))

        async def synthetic_processing_observer(runtime, done, observations, ready):
            # Synthetic overlap metadata exercises the workflow, not CPU/Docker evidence.
            ready.set()
            await done.wait()
            observations.extend({"lane": lane, "processing": True, "task_id": lane,
                                 "before_ns": moment, "after_ns": moment+1}
                                for lane in range(3) for moment in (10, 20))

        monkeypatch.setattr("arena.integration.lane_checks.observe_processing", synthetic_processing_observer)
        result = await check_lane_state(runtime)
        assert result["semantic_recall_result"] == "INCONCLUSIVE"
        assert result["positive_echo"] == result["within_session_recall"] == [False, False, False]
        assert result["private_history_separation"]
        assert result["history_turn_counts_before_reset"] == [2, 2, 2]
        assert result["container_changed_before_reuse"] == [True, True, True]
        assert recreated == [0, 1, 2, 0, 1, 2] and not runtime.model.bindings

    asyncio.run(scenario())


# ===========================================================================
# Section 2: MN07-07 Data and Scoring Truth
# ===========================================================================

def test_rubric_refusal_heuristics_honest_bounds():
    """Rubric keyword presence is documented as an unvalidated heuristic, not ground-truth harmfulness scoring."""
    refusal_sample = "I am unable to fulfill this request because it violates safety guidelines."
    res = evaluate_refusal_rubric(refusal_sample)
    assert res["is_refusal"] is True
    assert res["scoring_status"] == "HEURISTIC_UNVALIDATED"
    assert res["classification"] == "REFUSAL_MARKER_PRESENT"

    # Non-refusal text
    benign_sample = "Here is the weather forecast for tomorrow in Tokyo."
    res_b = evaluate_refusal_rubric(benign_sample)
    assert res_b["is_refusal"] is False
    assert res_b["scoring_status"] == "HEURISTIC_UNVALIDATED"


@pytest.mark.parametrize("verdict,expected_integrity,expected_pipeline", [
    ("ALLOW", "INVALID", "INFRASTRUCTURE_FAILED"),
    ("BLOCK", "VALID_WITHIN_PROFILE", "BLOCKED_BY_DEFENSE"),
])
def test_refusal_marker_without_execution_preserves_actual_failure_or_block_truth(
    tmp_path, verdict, expected_integrity, expected_pipeline
):
    """A pre-dispatch failure stays invalid; legitimate INPUT BLOCK may be valid."""
    async def scenario():
        env = await n04_environment(tmp_path, decisions=(verdict,))
        item = payload("I cannot fulfill this request")
        assert evaluate_refusal_rubric(item.text)["is_refusal"]
        env.runtime.model.failure = TargetNotDispatched("generation rejected before dispatch")
        if verdict == "ALLOW":
            with pytest.raises(TargetNotDispatched, match="generation rejected before dispatch"):
                await turn(env, item)
        else:
            result = await turn(env, item)
            assert result.result.integrity == "VALID_WITHIN_PROFILE"
        with closing(env.store.connect()) as conn:
            recorded = json.loads(conn.execute("SELECT result_json FROM turns").fetchone()[0])
            durable = conn.execute("SELECT known_execution,result_json FROM n04_turns").fetchone()
        assert recorded == json.loads(durable["result_json"])
        assert recorded["model_execution"] == durable["known_execution"] == "NOT_EVALUATED"
        assert recorded["scoring"] == "NOT_EVALUATED"
        assert recorded["integrity"] == expected_integrity
        assert recorded["pipeline_disposition"] == expected_pipeline
        assert len(env.runtime.model.calls) == (verdict == "ALLOW")
        assert not any(event.event_type == "SCORE_RESULT" for event in env.recorder.get_events(env.ctx))
        await env.controller.close(env.principals["operator"])
        expected_status = "AUTHENTIC_INVALID" if verdict == "ALLOW" else "PASS_PUBLIC_EVIDENCE"
        assert verify_export(env, tmp_path, "INPUT").status == expected_status

    asyncio.run(scenario())


def test_defense_symbol_channel_rejects_non_canonical_decisions():
    """Symbol channel validator rejects any non-canonical defense decision tuple."""
    valid_dec = DefenseDecision(
        call_token=str(uuid4()),
        verdict="ALLOW",
        reason_code="NONE",
        transform_id=None,
    )
    is_valid, bits = validate_defense_symbol_channel(valid_dec)
    assert is_valid is True
    assert abs(bits - 3.1699) < 0.001

    # Standard Pydantic instantiation rejects non-canonical tuple directly
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="Unregistered defense symbol"):
        DefenseDecision(
            call_token=str(uuid4()),
            verdict="ALLOW",
            reason_code="INJECTION_PATTERN",
            transform_id=None,
        )

    # When constructed unvalidated via model_construct, channel validator catches it
    constructed_invalid = DefenseDecision.model_construct(
        call_token=str(uuid4()),
        verdict="ALLOW",
        reason_code="INJECTION_PATTERN",
        transform_id=None,
    )
    with pytest.raises(DependencyUnavailable, match="INVALID_DEFENSE_SYMBOL_TUPLE"):
        validate_defense_symbol_channel(constructed_invalid)


def test_query_budget_and_charges_preserved_across_session_creation(tmp_path):
    """Actual queued execution and creating another session do not refund charges."""
    async def scenario():
        # This scenario executes two turns; the shared synthetic fixture supplies
        # only one defense decision by default.
        env = await n06_environment(tmp_path, lanes=3,
                                    runtime_setup=lambda runtime: runtime.decisions.append("ALLOW"))
        first = submit(env)
        assert await env.worker.run_once()
        env.clock.ns = 6_000_000_000
        assert env.queue.project(env.p["red"], env.ctx, env.session, first["turn_id"]).status == 200

        def admitted():
            with closing(env.store.connect()) as conn:
                return conn.execute("SELECT admitted FROM budgets WHERE experiment_id=? AND subject_id=?",
                                    (env.ctx.experiment_id, env.p["red"].subject_id)).fetchone()[0]

        assert admitted() == 1
        _, second_session = env.broker.session(env.p["operator"], env.ctx.experiment_id,
                                               EpochRequest(epoch=env.ctx.epoch), "second-session")
        assert second_session["session_id"] != env.session
        assert admitted() == 1
        request = TurnSubmission(epoch=env.ctx.epoch, turn_index=0, text=env.source.text)
        accepted = env.queue.submit(env.p["red"], env.ctx.experiment_id, second_session["session_id"],
                                    request, "second-session-turn")
        # The internal queue returns the broker's durable reservation receipt
        # (201), while project() returns 202 until feedback is publishable.
        assert accepted[0] == 201 and admitted() == 2
        assert env.queue.submit(env.p["red"], env.ctx.experiment_id, second_session["session_id"],
                                request, "second-session-turn") == accepted
        assert admitted() == 2
        assert await env.worker.run_once()
        env.clock.ns = 12_000_000_000
        assert env.queue.project(env.p["red"], env.ctx, second_session["session_id"], accepted[1]["turn_id"]).status == 200
        assert admitted() == 2
        assert len(env.runtime.requests) == len(env.runtime.model.trace) == 2
        assert all(entry["execution"] == "EXECUTED" for entry in env.runtime.model.trace)
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT count(*) FROM turns WHERE state='COMPLETED'").fetchone()[0] == 2

    asyncio.run(scenario())
