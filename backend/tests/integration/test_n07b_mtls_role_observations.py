"""Actual loopback mTLS status/feedback role views across synthetic run states."""

import asyncio
from contextlib import closing
import hashlib
import json
import time

from arena.contracts.api import EpochRequest, TurnSubmission
from arena.execution.lab import LocalMTLSPilot
from test_n06_execution import environment


ENDPOINTS = ("status", "feedback")
ROLES = ("red", "blue-human")


def _wire_request(env, index=0):
    return TurnSubmission(epoch=env.ctx.epoch, turn_index=index, text=env.source.text)


def _durable_snapshot(env):
    with closing(env.store.connect()) as conn:
        snapshot = {
            "experiment": tuple(conn.execute(
                "SELECT phase,integrity FROM experiments WHERE id=?", (env.ctx.experiment_id,)
            ).fetchone()),
            "sessions": tuple(tuple(row) for row in conn.execute(
                "SELECT id,quarantined FROM sessions WHERE experiment_id=? ORDER BY id",
                (env.ctx.experiment_id,),
            )),
            "budget_admissions": tuple(row[0] for row in conn.execute(
                "SELECT admitted FROM budgets ORDER BY rowid"
            )),
            "jobs": tuple(tuple(row) for row in conn.execute(
                "SELECT turn_id,state,known_execution,published FROM n06_jobs "
                "WHERE experiment_id=? ORDER BY turn_id", (env.ctx.experiment_id,),
            )),
            "turns": tuple(tuple(row) for row in conn.execute(
                "SELECT id,state FROM turns WHERE experiment_id=? ORDER BY id",
                (env.ctx.experiment_id,),
            )),
            "lab_actions": tuple(tuple(row) for row in conn.execute(
                "SELECT operation_id,acknowledged FROM n06_lab_actions "
                "WHERE experiment_id=? ORDER BY operation_id", (env.ctx.experiment_id,),
            )),
            "lab_run": tuple(conn.execute(
                "SELECT state FROM n06_lab_runs WHERE experiment_id=?", (env.ctx.experiment_id,)
            ).fetchone()),
            "n04_run": tuple(conn.execute(
                "SELECT state FROM n04_runs WHERE experiment_id=?", (env.ctx.experiment_id,)
            ).fetchone()),
        }
    snapshot["recorder_events"] = tuple(
        (event.sequence, event.event_type, event.outcome_code)
        for event in env.recorder.get_events(env.ctx)
    )
    snapshot["model_calls"] = len(env.runtime.model.calls)
    return snapshot


async def _prepare_state(env, lab, state):
    if state == "RUNNING_NO_TURNS":
        return

    turns_path = f"/v1/experiments/{env.ctx.experiment_id}/sessions/{env.session}/turns"
    if state == "WORKER_FAILURE_INVALID":
        status, body, _ = await asyncio.to_thread(
            lab.request, "red", "POST", turns_path,
            _wire_request(env).model_dump(exclude_none=True), "role-observation-failure",
        )
        assert status == 202
        turn_id = json.loads(body)["turn_id"]
        job = env.queue.claim(env.ctx, env.worker.worker_id)
        assert job and job["turn_id"] == turn_id
        env.queue.fail_claim(job, env.worker.worker_id, fallback="NOT_EVALUATED")
        return

    if state == "CANCELLATION_INVALID":
        path = f"/v1/experiments/{env.ctx.experiment_id}/sessions/{env.session}/cancel"
        status, body, _ = await asyncio.to_thread(
            lab.request, "red", "POST", path,
            EpochRequest(epoch=env.ctx.epoch).model_dump(exclude_none=True),
            "role-observation-cancel",
        )
        assert status == 202 and json.loads(body)["status"] == "CANCEL_REQUESTED"
        await lab.gateway.flush_actions()
        return

    raise AssertionError(f"unrecognized observation fixture: {state}")


def test_actual_mtls_status_and_feedback_are_fixed_role_views_across_run_states(tmp_path):
    async def scenario():
        await _exercise_matrix(tmp_path)

    asyncio.run(scenario())


async def _exercise_matrix(tmp_path):
    state_specs = (
        ("RUNNING_NO_TURNS", ("RUNNING", "PENDING")),
        ("WORKER_FAILURE_INVALID", ("INVALID", "INVALID")),
        ("CANCELLATION_INVALID", ("INVALID", "INVALID")),
    )
    stable_bodies = {}
    state_results = []

    for state, expected_run in state_specs:
        env = await environment(tmp_path / state.lower())
        env.queue.clock_ns = time.monotonic_ns
        lab = LocalMTLSPilot(
            env.worker, env.p["operator"], env.p, tmp_path / f"tls-{state.lower()}",
            admission_window_ms=100,
        )
        try:
            await _prepare_state(env, lab, state)
            with closing(env.store.connect()) as conn:
                actual_run = tuple(conn.execute(
                    "SELECT phase,integrity FROM experiments WHERE id=?", (env.ctx.experiment_id,)
                ).fetchone())
            assert actual_run == expected_run

            before = _durable_snapshot(env)
            path_base = f"/v1/experiments/{env.ctx.experiment_id}"
            requests = 0
            for role in ROLES:
                for endpoint in ENDPOINTS:
                    status, body, _ = await asyncio.to_thread(
                        lab.request, role, "GET", f"{path_base}/{endpoint}"
                    )
                    requests += 1
                    expected_status = "CONTROLLED" if role == "red" else "EMBARGOED"
                    assert status == 200 and len(body) == 4096
                    assert env.source.text.encode("utf-8") not in body
                    payload = json.loads(body)
                    assert set(payload) == {"schema_version", "status", "padding"}
                    assert payload["schema_version"] == "arena.execution.v1"
                    assert payload["status"] == expected_status
                    if role in stable_bodies:
                        assert body == stable_bodies[role]
                    else:
                        stable_bodies[role] = body
                    assert _durable_snapshot(env) == before

            denied_views = []
            for endpoint in ENDPOINTS:
                status, body, _ = await asyncio.to_thread(
                    lab.request, "operator", "GET", f"{path_base}/{endpoint}"
                )
                requests += 1
                assert status in {403, 404} and len(body) == 4096
                payload = json.loads(body)
                assert payload["schema_version"] == "arena.execution.v1"
                assert payload["status"] == "ERROR"
                assert payload.get("code") in {"FORBIDDEN", "NOT_FOUND"}
                assert env.source.text.encode("utf-8") not in body
                denied_views.append(body)
                assert _durable_snapshot(env) == before
            assert denied_views[0] == denied_views[1]
            state_results.append({
                "fixture": state,
                "experiment_phase_integrity": list(actual_run),
                "actual_mtls_gets": requests,
                "red_status": "CONTROLLED",
                "blue_human_status": "EMBARGOED",
                "operator_denied": True,
                "same_fixed_body_across_endpoints_and_states": True,
                "reads_side_effect_free": True,
                "durable_snapshot_sha256": hashlib.sha256(
                    repr(before).encode("utf-8")
                ).hexdigest(),
            })
        finally:
            await lab.close()

    observation = {
        "transport": "LOCAL_HTTPS_MUTUAL_TLS",
        "scope": "N07B_ACTUAL_MTLS_ROLE_SCOPED_STATUS_FEEDBACK_OBSERVATIONS",
        "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
        "roles": list(ROLES),
        "endpoints": list(ENDPOINTS),
        "response_bytes": 4096,
        "states": state_results,
        "role_body_sha256": {
            role: hashlib.sha256(stable_bodies[role]).hexdigest()
            for role in ROLES
        },
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
    }
    print("N07B_MTLS_ROLE_OBSERVATIONS " + json.dumps(observation, sort_keys=True))
