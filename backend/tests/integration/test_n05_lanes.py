"""Synthetic fault/race checks; real Docker/CPU evidence comes from the N05 CLI."""

import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from arena.contracts.api import TargetRequest, TargetResponse
from arena.contracts.common import Context
from arena.integration.lanes import ThreeLaneModel, check_capacity, cpu_set, select_cpus
from arena.integration.isolation import processing_overlap, zero_clock_offsets
from arena.ports import DependencyUnavailable, TargetNotDispatched


def context():
    return Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)


def request(ctx, session, index=0):
    return TargetRequest(**ctx.model_dump(), session_id=session, attempt_id=str(uuid4()),
                         turn_index=index, text="synthetic", max_output_tokens=16)


class Model:
    def __init__(self):
        self.entered, self.release = asyncio.Event(), asyncio.Event()
        self.failure = None
        self.resets = []

    async def infer(self, req):
        self.entered.set()
        await self.release.wait()
        if self.failure:
            raise self.failure
        return req

    async def reset(self, session):
        self.resets.append(session)
        if self.failure:
            raise self.failure


class ConcurrentTurnGate:
    """Hold each synthetic turn until all three lane adapters have entered."""

    def __init__(self, turn_count):
        self.arrivals = [set() for _ in range(turn_count)]
        self.ready = [asyncio.Event() for _ in range(turn_count)]
        self.release = [asyncio.Event() for _ in range(turn_count)]

    async def wait(self, lane, turn_index):
        self.arrivals[turn_index].add(lane)
        if self.arrivals[turn_index] == {0, 1, 2}:
            self.ready[turn_index].set()
        await self.release[turn_index].wait()


class DeterministicModel:
    """Pure-rule adapter for exact routing/output comparisons, not real inference."""

    def __init__(self, lane, gate=None):
        self.lane, self.gate, self.calls = lane, gate, []

    async def infer(self, req):
        self.calls.append(req)
        if self.gate is not None:
            await self.gate.wait(self.lane, req.turn_index)
        identity = {name: getattr(req, name) for name in (
            "domain_id", "experiment_id", "epoch", "attempt_id", "session_id", "turn_index"
        )}
        return TargetResponse(
            **identity,
            text=f"rule:{self.lane}:{req.turn_index}:{req.text}",
            input_tokens=len(req.text.split()),
            output_tokens=1,
            duration_us=7,
        )


def pool():
    cells = [SimpleNamespace(container="synthetic-" + str(i), model=Model()) for i in range(3)]
    made = []
    def recreate(i):
        made.append(i)
        return SimpleNamespace(container="synthetic-new-" + str(i), model=Model())
    return ThreeLaneModel(cells, recreate), made


def test_sticky_context_lane_ownership_and_unbound_requests():
    model, _ = pool()
    ctx, session = context(), str(uuid4())
    model.bind_session(session, 1, ctx)
    model.bind_session(session, 1, ctx)
    assert model.get_assigned_lane(session) == "lane-1"
    for sid, lane, binding in [(session, 2, ctx), (str(uuid4()), 1, ctx), (session, 1, context())]:
        with pytest.raises(DependencyUnavailable, match="BINDING_CONFLICT"):
            model.bind_session(sid, lane, binding)
    for req in [request(ctx, str(uuid4())), request(context(), session)]:
        with pytest.raises(TargetNotDispatched, match="BROKER_BINDING_REQUIRED"):
            asyncio.run(model.infer(req))


def test_three_active_lanes_and_same_lane_race_rejection():
    async def scenario():
        model, _ = pool()
        ctx, sessions = context(), [str(uuid4()) for _ in range(3)]
        for i, session in enumerate(sessions):
            model.bind_session(session, i, ctx)
        tasks = [asyncio.create_task(model.infer(request(ctx, sid))) for sid in sessions]
        await asyncio.wait_for(asyncio.gather(*(cell.model.entered.wait() for cell in model.cells)), 2)
        assert model.active == {0, 1, 2}
        with pytest.raises(TargetNotDispatched, match="ONE_UNRESOLVED"):
            await model.infer(request(ctx, sessions[0], 1))
        with pytest.raises(DependencyUnavailable, match="NOT_SAFE_TO_RESET"):
            await model.reset(sessions[0])
        for cell in model.cells:
            cell.model.release.set()
        await asyncio.gather(*tasks)
        assert model.active == set()
        assert len(model.trace) == 3
    asyncio.run(scenario())


def test_deterministic_serial_and_concurrent_outputs_match_across_three_lanes():
    async def scenario():
        turn_count = 4
        contexts = [context() for _ in range(3)]
        sessions = [str(uuid4()) for _ in range(3)]
        requests = [
            [request(contexts[lane], sessions[lane], turn) for turn in range(turn_count)]
            for lane in range(3)
        ]

        async def make_pool(gate=None):
            cells = [SimpleNamespace(
                container=f"deterministic-{lane}", model=DeterministicModel(lane, gate)
            ) for lane in range(3)]
            model = ThreeLaneModel(cells, lambda lane: cells[lane])
            for lane in range(3):
                model.bind_session(sessions[lane], lane, contexts[lane])
            return model

        serial = await make_pool()
        serial_results = {}
        for lane in range(3):
            for req in requests[lane]:
                response = await serial.infer(req)
                serial_results[(lane, req.turn_index)] = response.model_dump(mode="json")

        gate = ConcurrentTurnGate(turn_count)
        concurrent = await make_pool(gate)

        async def run_lane(lane):
            results = []
            for req in requests[lane]:
                response = await concurrent.infer(req)
                results.append((lane, req.turn_index, response.model_dump(mode="json")))
            return results

        workers = [asyncio.create_task(run_lane(lane)) for lane in range(3)]
        for turn in range(turn_count):
            await asyncio.wait_for(gate.ready[turn].wait(), timeout=2)
            assert gate.arrivals[turn] == {0, 1, 2}
            assert concurrent.active == {0, 1, 2}
            gate.release[turn].set()
        concurrent_rows = await asyncio.gather(*workers)
        concurrent_results = {
            (lane, turn): response
            for lane_rows in concurrent_rows
            for lane, turn, response in lane_rows
        }

        assert concurrent_results == serial_results
        for lane in range(3):
            expected_requests = requests[lane]
            for model in (serial, concurrent):
                assert model.get_assigned_lane(sessions[lane]) == f"lane-{lane}"
                assert model.cells[lane].model.calls == expected_requests
                lane_trace = [row for row in model.trace if row["lane"] == lane]
                assert [row["turn_id"] for row in lane_trace] == [req.attempt_id for req in expected_requests]
                assert all(row["session_id"] == sessions[lane] and row["execution"] == "EXECUTED"
                           for row in lane_trace)
        assert len(serial.trace) == len(concurrent.trace) == 3 * turn_count
        assert concurrent.active == set()

    asyncio.run(scenario())


@pytest.mark.parametrize("failure", [DependencyUnavailable("LOST_ACK"), asyncio.CancelledError()])
def test_ambiguous_or_cancelled_lane_is_quarantined_without_affecting_peers(failure):
    async def scenario():
        model, made = pool()
        ctx, session = context(), str(uuid4())
        model.bind_session(session, 0, ctx)
        model.cells[0].model.release.set()
        model.cells[0].model.failure = failure
        with pytest.raises(type(failure)):
            await model.infer(request(ctx, session))
        assert model.quarantined == {0} and model.trace[0]["execution"] == "UNKNOWN"
        with pytest.raises(TargetNotDispatched, match="QUARANTINED"):
            await model.infer(request(ctx, session))
        with pytest.raises(DependencyUnavailable, match="NOT_SAFE_TO_RESET"):
            await model.reset(session)
        model.bind_session(str(uuid4()), 1, ctx)
        assert not made
    asyncio.run(scenario())


def test_not_dispatched_is_not_poisoned_and_successful_reset_recreates_before_reuse():
    async def scenario():
        model, made = pool()
        ctx, session = context(), str(uuid4())
        model.bind_session(session, 0, ctx)
        model.cells[0].model.release.set()
        model.cells[0].model.failure = TargetNotDispatched("TOKEN_CAP")
        with pytest.raises(TargetNotDispatched):
            await model.infer(request(ctx, session))
        assert not model.quarantined and model.trace[0]["execution"] == "NOT_EVALUATED"
        model.cells[0].model.failure = None
        await model.reset(session)
        assert made == [0] and not model.bindings and model.cells[0].container == "synthetic-new-0"
        with pytest.raises(DependencyUnavailable, match="BINDING_INVALID"):
            model.bind_session(session, 0, ctx)
        model.bind_session(str(uuid4()), 0, context())
    asyncio.run(scenario())


def test_reset_failure_retains_owner_and_quarantine():
    async def scenario():
        model, made = pool()
        ctx, session = context(), str(uuid4())
        model.bind_session(session, 2, ctx)
        model.cells[2].model.failure = DependencyUnavailable("RESET_ACK_LOST")
        with pytest.raises(DependencyUnavailable):
            await model.reset(session)
        assert model.owners[2] == session and model.quarantined == {2} and not made
        with pytest.raises(DependencyUnavailable):
            model.bind_session(str(uuid4()), 2, ctx)
    asyncio.run(scenario())


def observation():
    return {"allowed_cpus": list(range(16)), "siblings": {str(i): f"{i//2*2}-{i//2*2+1}" for i in range(16)},
            "mem_available_bytes": 10 * 1024**3}


def test_capacity_uses_whole_sibling_groups_and_rejects_overlap_low_memory_or_changed_topology():
    info = observation()
    cpus, defense = select_cpus(info)
    admission = SimpleNamespace(model_cpusets=cpus, defense_cpuset=defense, minimum_available_memory_bytes=7*1024**3)
    check_capacity(admission, info)
    assert cpus == ("0,1,2,3", "4,5,6,7", "8,9,10,11")
    for broken in [dict(info, mem_available_bytes=0), dict(info, allowed_cpus=[0, 1]),
                   dict(info, siblings={**info["siblings"], "0": "0,15"})]:
        with pytest.raises(DependencyUnavailable):
            check_capacity(admission, broken)
    with pytest.raises(DependencyUnavailable, match="OVERLAPPING"):
        check_capacity(SimpleNamespace(model_cpusets=("0,1", "0,1", "4,5"), defense_cpuset=defense), info)


@pytest.mark.parametrize("bad", ["", "1-0", "0,0", "0-2,1", "x", "1--2", "65536", "-1"])
def test_invalid_cpu_sets_fail_closed(bad):
    with pytest.raises(ValueError):
        cpu_set(bad)


def test_overlap_requires_two_same_task_busy_observations_per_lane_and_common_interval():
    rows = [{"lane": lane, "processing": True, "task_id": lane, "before_ns": t, "after_ns": t+1}
            for lane in range(3) for t in (10+lane, 20+lane)]
    assert processing_overlap(rows)["conservative_overlap_ns"] == 7
    assert processing_overlap(rows[:4])["result"] == "INCONCLUSIVE"
    rows[-1]["task_id"] = 99
    assert processing_overlap(rows)["result"] == "INCONCLUSIVE"


def test_clock_comparison_requires_zero_monotonic_and_boottime_offsets():
    assert zero_clock_offsets("monotonic 0 0\nboottime 0 0\n")
    for raw in ["monotonic 0 0", "monotonic 0 0\nmonotonic 0 0", "monotonic 1 0\nboottime 0 0",
                "monotonic 0 0\nboottime 0 1", "monotonic 0 0 ignored\nboottime 0 0"]:
        assert not zero_clock_offsets(raw)


def test_entire_canary_workflow_with_synthetic_model_reports_semantic_inconclusive(monkeypatch):
    from arena.adapters.llama_adapter import LlamaModelAdapter
    from arena.integration.lane_checks import check_lane_state
    async def scenario():
        cells = [SimpleNamespace(container="synthetic-" + str(i),
                 model=LlamaModelAdapter(synthetic_mode=True, max_lanes=1)) for i in range(3)]
        recreated = []
        def recreate(lane):
            recreated.append(lane)
            return SimpleNamespace(container="synthetic-recreated-" + str(len(recreated)),
                                   model=LlamaModelAdapter(synthetic_mode=True, max_lanes=1))
        runtime = SimpleNamespace(cells=cells, model=ThreeLaneModel(cells, recreate))
        async def synthetic_observer(runtime, done, observations, ready):
            ready.set()
            await done.wait()
            observations.extend({"lane": lane, "processing": True, "task_id": lane,
                                 "before_ns": time, "after_ns": time+1}
                                for lane in range(3) for time in (10, 20))
        monkeypatch.setattr("arena.integration.lane_checks.observe_processing", synthetic_observer)
        result = await check_lane_state(runtime)
        assert result["semantic_recall_result"] == "INCONCLUSIVE"
        assert result["private_history_separation"] and result["history_turn_counts_before_reset"] == [2, 2, 2]
        assert recreated == [0, 1, 2, 0, 1, 2] and not runtime.model.bindings
    asyncio.run(scenario())
