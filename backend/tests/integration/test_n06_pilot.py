"""Local pilot plumbing uses synthetic adapters; only a separate real run proves inference."""

import asyncio
from contextlib import closing
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from arena.contracts.api import EpochRequest, TurnSubmission
from arena.execution.pilot import LocalWorkerPilot, WorkerSample, candidate_from_pilot
from arena.execution.policy import FeedbackPolicy
from arena.integration.cli import run
from arena.ports import DependencyUnavailable
from test_n06_execution import environment


def vectors():
    policy = FeedbackPolicy(policy_id="structural-test-only", run_label="REAL_PUBLIC",
                            execution_deadline_ms=10000, release_floor_ms=11000, body_bytes=4096)
    samples = []
    for i in range(6):
        base = i * 100_000_000_000
        samples.append(WorkerSample(sample_index=i, lane=i % 3, admitted_ns=base,
            authorized_observed_ns=base + (2_000_000_000 if i < 5 else 4_000_000_000),
            deadline_ns=base + 10_000_000_000, release_ns=base + 11_000_000_000,
            published_observed_ns=base + 11_001_000_000, body_bytes=4096, unpadded_body_bytes=1900,
            pending_status=202, final_status=200, replay_identical=True))
    return samples, policy


def test_candidate_uses_fixed_conservative_rule_and_never_claims_public_calibration():
    samples, policy = vectors()
    candidate, metadata = candidate_from_pilot(samples, policy)
    assert (candidate.execution_deadline_ms, candidate.release_floor_ms, candidate.body_bytes) == (8000, 9000, 4096)
    assert candidate.scope == "N06_COMPONENT_ONLY_UNCALIBRATED"
    assert metadata["maximum_observed_worker_ns"] == 4_000_000_000
    assert not metadata["calibrated_public_policy"] and not metadata["p99_established"]


@pytest.mark.parametrize("change", ["missing", "duplicate", "lane", "bucket", "deadline", "run-label"])
def test_candidate_rejects_incomplete_or_different_workload_policy(change):
    samples, policy = vectors()
    if change == "missing": samples.pop()
    elif change == "duplicate": samples[-1] = samples[0]
    elif change == "run-label": policy = policy.model_copy(update={"run_label": "SYNTHETIC_MOCK"})
    else:
        field, value = {"lane": ("lane", 2), "bucket": ("body_bytes", 8192), "deadline": ("deadline_ns", 10_100_000_000)}[change]
        samples[0] = samples[0].model_copy(update={field: value})
    with pytest.raises((ValueError, DependencyUnavailable)):
        candidate_from_pilot(samples, policy)


def test_sample_rejects_early_publication_and_no_silent_policy_cap_increase():
    samples, policy = vectors()
    with pytest.raises(ValueError, match="CLOCK_OR_DEADLINE"):
        WorkerSample.model_validate(samples[0].model_dump() | {"published_observed_ns": 1})
    long = FeedbackPolicy(policy_id="test", run_label="REAL_PUBLIC", execution_deadline_ms=120000, release_floor_ms=120000, body_bytes=4096)
    raw = [s.model_dump() | {"authorized_observed_ns": s.admitted_ns + 100_000_000_000,
            "deadline_ns": s.admitted_ns + 120_000_000_000, "release_ns": s.admitted_ns + 120_000_000_000,
            "published_observed_ns": s.admitted_ns + 120_001_000_000} for s in samples]
    with pytest.raises(DependencyUnavailable, match="EXCEEDS_COMPONENT"):
        candidate_from_pilot(raw, long)


def test_local_pilot_executes_six_ordered_turns_with_actual_evidence_and_no_replay_dispatch(tmp_path):
    async def scenario():
        env = await environment(tmp_path, lanes=3, execution_deadline_ms=5000, release_floor_ms=5100)
        env.runtime.decisions = ["ALLOW"] * 6
        env.queue.clock_ns = time.monotonic_ns
        runner = LocalWorkerPilot(env.worker)
        sessions = [env.session] + [env.broker.session(env.p["operator"], env.ctx.experiment_id,
                    EpochRequest(epoch=env.ctx.epoch), "session-" + str(i))[1]["session_id"] for i in (1, 2)]
        observed = []
        async def one(i):
            return await runner.turn(env.p["red"], sessions[i % 3],
                TurnSubmission(epoch=env.ctx.epoch, turn_index=i // 3, text=env.source.text),
                "pilot-" + str(i), index=i, lane=i % 3)
        for start in (0, 3):
            observed.extend(await asyncio.gather(*(one(i) for i in range(start, start+3))))
        assert all(x.result.result.model_execution == "EXECUTED" for x in observed)
        assert len({x.result.turn_id for x in observed}) == 6
        assert sum(x["execution"] == "EXECUTED" for x in env.runtime.model.trace) == 6
        assert all(x.sample.published_observed_ns >= x.sample.release_ns and x.sample.body_bytes == 4096 for x in observed)
        assert env.broker.status(env.p["blue-human"], env.ctx.experiment_id, True)[1] == {"status": "EMBARGOED"}
        assert await env.worker.drain() and not await env.worker.run_once()
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 6
            assert conn.execute("SELECT count(*) FROM n06_jobs WHERE state='AUTHORIZED' AND published=1").fetchone()[0] == 6
        with pytest.raises(DependencyUnavailable, match="FRESH_SOLE_WORKER"):
            await one(0)
    asyncio.run(scenario())


def test_policy_option_cannot_silently_run_without_independent_trust():
    args = SimpleNamespace(n06_policy=Path("unused.json"), n06_policy_public_key=None, n06_policy_key_id=None)
    with pytest.raises(ValueError, match="INDEPENDENT_TRUST_REQUIRED"):
        asyncio.run(run(args))
