"""Actual-mTLS denial of unauthorized cancellation mutations in N07B.

This probes the local HTTPS participant gateway with a valid current-epoch
cancel request from roles that must not be able to invalidate a run. The
fixture uses synthetic components and makes no inference or deployment claim.
"""

import asyncio
from contextlib import closing
import hashlib
import json
import time

from arena.contracts.api import EpochRequest
from arena.execution.lab import LocalMTLSPilot
from test_n06_execution import environment


SCOPE = "N07B_ACTUAL_MTLS_UNAUTHORIZED_CANCEL_DENIAL"
DENIED_ROLES = ("blue-human", "operator")


def _durable_snapshot(env):
    """Capture relevant control state without reading private payload contents."""
    with closing(env.store.connect()) as conn:
        snapshot = {
            "experiment": tuple(conn.execute(
                "SELECT phase,integrity FROM experiments WHERE id=?",
                (env.ctx.experiment_id,),
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
                "WHERE experiment_id=? ORDER BY turn_id",
                (env.ctx.experiment_id,),
            )),
            "turns": tuple(tuple(row) for row in conn.execute(
                "SELECT id,state FROM turns WHERE experiment_id=? ORDER BY id",
                (env.ctx.experiment_id,),
            )),
            "lab_actions": tuple(tuple(row) for row in conn.execute(
                "SELECT operation_id,acknowledged FROM n06_lab_actions "
                "WHERE experiment_id=? ORDER BY operation_id",
                (env.ctx.experiment_id,),
            )),
            "idempotency_count": conn.execute(
                "SELECT count(*) FROM idempotency WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()[0],
            "payload_count": conn.execute(
                "SELECT count(*) FROM payloads WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()[0],
            "lab_run": tuple(conn.execute(
                "SELECT state FROM n06_lab_runs WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()),
            "n04_run": tuple(conn.execute(
                "SELECT state FROM n04_runs WHERE experiment_id=?",
                (env.ctx.experiment_id,),
            ).fetchone()),
        }
    snapshot["recorder_events"] = tuple(
        (event.sequence, event.event_type, event.outcome_code)
        for event in env.recorder.get_events(env.ctx)
    )
    snapshot["model_calls"] = len(env.runtime.model.calls)
    return snapshot


def test_actual_mtls_blue_and_operator_cancel_requests_are_denied_without_mutation(tmp_path):
    async def scenario():
        env = await environment(tmp_path / "fixture")
        env.queue.clock_ns = time.monotonic_ns
        lab = LocalMTLSPilot(
            env.worker,
            env.p["operator"],
            env.p,
            tmp_path / "tls",
            admission_window_ms=100,
        )
        try:
            before = _durable_snapshot(env)
            assert before["experiment"] == ("RUNNING", "PENDING")
            assert before["sessions"] == ((env.session, 0),)
            assert before["budget_admissions"] == (0,)
            assert before["jobs"] == before["turns"] == before["lab_actions"] == ()
            assert before["model_calls"] == 0

            path = (
                f"/v1/experiments/{env.ctx.experiment_id}/sessions/"
                f"{env.session}/cancel"
            )
            request = EpochRequest(epoch=env.ctx.epoch).model_dump(exclude_none=True)
            observations = []
            for role in DENIED_ROLES:
                status, body, _ = await asyncio.to_thread(
                    lab.request,
                    role,
                    "POST",
                    path,
                    request,
                    f"n07b-hostile-cancel-{role}",
                )
                payload = json.loads(body)
                assert status in {403, 404}
                assert len(body) == 4096
                assert payload["schema_version"] == "arena.execution.v1"
                assert payload["status"] == "ERROR"
                assert payload.get("code") in {"FORBIDDEN", "NOT_FOUND"}
                assert env.source.text.encode("utf-8") not in body
                assert _durable_snapshot(env) == before
                observations.append({
                    "role": role,
                    "http_status": status,
                    "envelope_status": payload["status"],
                    "error_code": payload["code"],
                    "response_bytes": len(body),
                    "response_sha256": hashlib.sha256(body).hexdigest(),
                })

            observation = {
                "scope": SCOPE,
                "transport": "LOCAL_HTTPS_MUTUAL_TLS",
                "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
                "fixture_state": list(before["experiment"]),
                "valid_epoch_cancel_requests": len(observations),
                "roles": [item["role"] for item in observations],
                "denials": observations,
                "response_bytes": 4096,
                "durable_snapshot_sha256": hashlib.sha256(
                    repr(before).encode("utf-8")
                ).hexdigest(),
                "side_effect_free": _durable_snapshot(env) == before,
                "real_inference_performed": False,
                "full_n07_acceptance": False,
                "full_arena_acceptance": False,
                "guarantee_tier_achieved": None,
            }
            assert observation["side_effect_free"] is True
            print("N07B_MTLS_HOSTILE_CANCEL " + json.dumps(observation, sort_keys=True))
        finally:
            await lab.close()

    asyncio.run(scenario())
