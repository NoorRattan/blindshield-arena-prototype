"""Admission-ACK uncertainty and measurement failure accounting regressions."""

import asyncio
from contextlib import closing
import copy
import json

import pytest

from arena.contracts.api import TurnSubmission
from arena.execution.transport import ParticipantGateway
from arena.measurement.evaluation import analyze
from arena.measurement.observer import observe_turn
from test_n06_execution import environment


def test_lost_admission_ack_retries_exact_identity_with_one_actual_charge_and_execution(tmp_path):
    async def scenario():
        env = await environment(tmp_path, sealed_transport=True, admission_window_ms=1000)
        trust = env.admission.trust
        gate = ParticipantGateway(env.p["operator"], env.worker, env.admission.plan.transport,
            trust.transport_public_key, trust.transport_key_id, admission=env.admission)
        request = TurnSubmission(epoch=env.ctx.epoch, turn_index=0, text=env.source.text)
        acks = []
        async def send(method, turn):
            if method == "POST":
                status, raw = gate.submit(env.p["red"], env.session, request, "one-original-key")
                acks.append(raw)
                if len(acks) == 1: raise ConnectionResetError("synthetic lost ACK")
                return status, raw, 1
            env.clock.ns = 1_000_000_000
            assert await env.worker.run_once()
            env.clock.ns = 6_000_000_000
            result = env.queue.project(env.p["red"], env.ctx, env.session, turn)
            return result.status, result.body, 1
        async def sleep(seconds): env.clock.ns += int(seconds*1e9)
        observed = await observe_turn(send, floor_ms=6000, clock=env.clock, sleep=sleep)
        assert observed["status"] == 200 and observed["accepted"] and len(acks) == 2 and acks[0] == acks[1]
        assert observed["admission_attempts"][0]["status"] == 0
        assert observed["latency_ns"] == 6_000_000_000
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 1
            assert conn.execute("SELECT count(*) FROM turns").fetchone()[0] == 1
        assert len(env.runtime.model.calls) == 1
    asyncio.run(scenario())


def test_closed_round_retry_and_terminal_rejection_are_bounded_and_visible():
    async def scenario():
        now, calls = [0], []
        async def sleep(seconds): now[0] += int(seconds*1e9)
        async def send(method, turn):
            calls.append(method)
            if len(calls) == 1:return 429, b'{"status":"RETRY_LATER"}', 1
            if method == "POST":return 202, b'{"status":"ACCEPTED","turn_id":"opaque-test"}', 1
            return 200, b"x"*4096, 1
        row = await observe_turn(send, floor_ms=6000, clock=lambda:now[0], sleep=sleep)
        assert row["status"] == 200 and [a["status"] for a in row["admission_attempts"]] == [429,202]
        async def rejected(*args):return 409,b'{"status":"ERROR"}',1
        row = await observe_turn(rejected, floor_ms=6000, clock=lambda:now[0], sleep=sleep)
        assert not row["accepted"] and row["error_type"] == "ADMISSION_REJECTED" and len(row["admission_attempts"]) == 1
    asyncio.run(scenario())


def vector():
    plan = {"turns_per_campaign":6,"selection_campaigns_per_arm":2,"validation_campaigns_per_arm":2,
        "body_bytes":4096,"seed":261022,"shaped_envelope":{"point":[.4,.6],"bootstrap_95":[.35,.65]},
        "scope":"SYNTHETIC_UNIT_VECTOR_ONLY","real_model":False}
    rows = [dict(arm=arm,phase=phase,campaign=campaign,index=i,label=i%2,
        latency_ns=1000 if arm=="SHAPED" else (10 if i%2 else 200),status=200,body_bytes=4096,error_type=None,
        admission_attempts=[{"status":202}],poll_errors=[],early_publication=arm!="SHAPED")
        for arm in ("SHAPED","UNSHAPED_SYNTHETIC_CONTROL") for phase in ("selection","validation")
        for campaign in range(2) for i in range(6)]
    return rows,plan


def test_analysis_never_hides_recovered_retries_or_partial_observations():
    rows,plan=vector()
    assert analyze(rows,plan)["result"] == "WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE"
    failed=copy.deepcopy(rows);failed[0]["admission_attempts"].insert(0,{"status":429})
    assert analyze(failed,plan)["result"] == "INCONCLUSIVE_OR_OUTSIDE_ENVELOPE"
    failed=copy.deepcopy(rows);failed[0]["poll_errors"]=["ConnectionResetError"]
    assert analyze(failed,plan)["result"] == "INCONCLUSIVE_OR_OUTSIDE_ENVELOPE"
    with pytest.raises(ValueError):analyze(rows[:-1],plan)


def test_measurement_campaign_preserves_allow_sanitize_block_and_offline_authority(tmp_path):
    from pathlib import Path
    import sys
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/"tools"))
    from measure_n06_release import campaign, protocol
    rows=asyncio.run(campaign(tmp_path/"functional","SHAPED","functional",0,[0,2,1],protocol("mock")))
    assert [(r["status"],r["defense_verdict"],r["known_execution"]) for r in rows] == [
        (200,"ALLOW","EXECUTED"),(200,"SANITIZE","EXECUTED"),(200,"BLOCK","NOT_EVALUATED")]
    authority=json.loads((tmp_path/"functional/authority.json").read_bytes())
    assert authority["private_openings"]==3 and authority["sealed_profile_verified"] and authority["blue_projection_constant"]
    metrics=json.loads((tmp_path/"functional/dispatch-metrics.json").read_bytes())
    assert all(set(row)=={"role","method","status","duration_ns"} for row in metrics)
