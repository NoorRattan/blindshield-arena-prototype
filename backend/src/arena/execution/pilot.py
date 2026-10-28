"""Trusted local worker measurements, not public HTTP or calibration authority."""

import asyncio
from contextlib import closing
from dataclasses import dataclass
import json
from typing import Annotated, Literal

from pydantic import Field, model_validator

from arena.contracts.api import AttemptResult
from arena.contracts.common import WireModel
from arena.contracts.evidence import TurnFeedback
from arena.integration.controller import InternalTurnResult
from arena.ports import DependencyUnavailable
from .policy import FeedbackPolicy


Nanoseconds = Annotated[int, Field(strict=True, ge=0)]


class WorkerSample(WireModel):
    sample_index: Annotated[int, Field(strict=True, ge=0, le=23)]
    lane: Annotated[int, Field(strict=True, ge=0, le=2)]
    admitted_ns: Nanoseconds
    authorized_observed_ns: Nanoseconds
    deadline_ns: Nanoseconds
    release_ns: Nanoseconds
    published_observed_ns: Nanoseconds
    body_bytes: Annotated[int, Field(strict=True, ge=2048, le=131072)]
    unpadded_body_bytes: Annotated[int, Field(strict=True, ge=1, le=131072)]
    pending_status: Literal[202]
    final_status: Literal[200]
    replay_identical: Literal[True]

    @model_validator(mode="after")
    def ordered(self):
        if not (self.admitted_ns <= self.authorized_observed_ns < self.deadline_ns
                <= self.release_ns <= self.published_observed_ns):
            raise ValueError("WORKER_SAMPLE_CLOCK_OR_DEADLINE_INVALID")
        if self.unpadded_body_bytes > self.body_bytes:
            raise ValueError("WORKER_SAMPLE_BODY_INVALID")
        return self


@dataclass(frozen=True)
class MeasuredTurn:
    result: InternalTurnResult
    sample: WorkerSample


class LocalWorkerPilot:
    """Sole in-process worker, fresh queued turns, at most three concurrent calls.

    Admission and claim execute synchronously before run_once's first await, so
    each fresh submission is the next queued job in this trusted CLI lifecycle.
    It is not a multi-worker service, cold-recovery path or participant API.
    """

    def __init__(self, worker):
        self.worker, self.queue = worker, worker.queue
        self.controller = worker.controller

    async def turn(self, principal, session_id, request, key, *, index, lane):
        _, receipt = self.queue.submit(principal, self.controller.identifier, session_id, request, key)
        with closing(self.queue.store.connect()) as conn:
            job = conn.execute("SELECT * FROM n06_jobs WHERE turn_id=?", (receipt["turn_id"],)).fetchone()
            queued = conn.execute("SELECT turn_id FROM n06_jobs WHERE experiment_id=? AND state='QUEUED' "
                                  "ORDER BY admitted_ns,turn_id LIMIT 1", (self.controller.identifier,)).fetchone()
        if not job or job["state"] != "QUEUED" or not queued or queued[0] != job["turn_id"]:
            raise DependencyUnavailable("PILOT_REQUIRES_FRESH_SOLE_WORKER_ADMISSION")
        ctx = self.controller.ctx
        pending = self.queue.project(principal, ctx, session_id, job["turn_id"])
        if pending.status != 202 or not await self.worker.run_once():
            raise DependencyUnavailable("PILOT_WORKER_CLAIM_REQUIRED")
        authorized_at = self.queue.clock_ns()
        with closing(self.queue.store.connect()) as conn:
            finished = conn.execute("SELECT state FROM n06_jobs WHERE turn_id=?", (job["turn_id"],)).fetchone()
            actual = conn.execute("SELECT result_json FROM n04_turns WHERE turn_id=? AND state='DONE'", (job["turn_id"],)).fetchone()
        if not finished or finished[0] != "AUTHORIZED" or not actual:
            raise DependencyUnavailable("PILOT_WORKER_DID_NOT_AUTHORIZE_FEEDBACK")
        while self.queue.clock_ns() < job["release_ns"]:
            await asyncio.sleep((job["release_ns"] - self.queue.clock_ns()) / 1_000_000_000)
        projected = self.queue.project(principal, ctx, session_id, job["turn_id"])
        published_at = self.queue.clock_ns()
        if projected.status != 200:
            raise DependencyUnavailable("PILOT_AUTHORIZED_PUBLICATION_REQUIRED")
        feedback = TurnFeedback.model_validate_json(projected.body)
        before = tuple(self.controller.recorder.get_events(ctx))
        retry = self.queue.submit(principal, self.controller.identifier, session_id, request, key)
        replay = self.queue.project(principal, ctx, session_id, job["turn_id"])
        if retry[1] != receipt or replay != projected or tuple(self.controller.recorder.get_events(ctx)) != before:
            raise DependencyUnavailable("PILOT_REPLAY_CHANGED_AUTHORIZED_RESULT")
        unpadded = {**json.loads(projected.body), "padding": ""}
        sample = WorkerSample(sample_index=index, lane=lane, admitted_ns=job["admitted_ns"],
            authorized_observed_ns=authorized_at, deadline_ns=job["deadline_ns"], release_ns=job["release_ns"],
            published_observed_ns=published_at, body_bytes=len(projected.body),
            unpadded_body_bytes=len(json.dumps(unpadded, separators=(",", ":"), ensure_ascii=True).encode("ascii")),
            pending_status=pending.status, final_status=projected.status, replay_identical=True)
        outcome = AttemptResult.model_validate_json(actual[0])
        return MeasuredTurn(InternalTurnResult(job["turn_id"], outcome, feedback.public_reply, feedback.feedback_receipt), sample)


def candidate_from_pilot(samples, policy, *, policy_id="n06-local-jbb6-candidate.v1"):
    """Conservative six-sample engineering estimate; never a p99 or security bound.

    Round 1.5 * max observed admission-to-authorization plus two seconds up to
    whole seconds (minimum five), then add one second for the common floor.
    This rule is fixed in source before measuring; byte bucket stays unchanged.
    """
    samples = [WorkerSample.model_validate(s.model_dump() if isinstance(s, WorkerSample) else s) for s in samples]
    policy = FeedbackPolicy.model_validate(policy.model_dump())
    if policy.run_label != "REAL_PUBLIC" or len(samples) != 6 or sorted(s.sample_index for s in samples) != list(range(6)):
        raise DependencyUnavailable("SIX_REAL_PILOT_SAMPLES_REQUIRED")
    for sample in samples:
        if (sample.lane != sample.sample_index % 3 or sample.body_bytes != policy.body_bytes
            or sample.deadline_ns - sample.admitted_ns != policy.execution_deadline_ms * 1_000_000
            or sample.release_ns - sample.admitted_ns != policy.release_floor_ms * 1_000_000):
            raise DependencyUnavailable("PILOT_SAMPLE_POLICY_MISMATCH")
    maximum = max(s.authorized_observed_ns - s.admitted_ns for s in samples)
    deadline_ms = max(5000, ((maximum * 3 + 1) // 2 + 2_000_000_000 + 999_999_999) // 1_000_000_000 * 1000)
    if deadline_ms > 119000:
        raise DependencyUnavailable("PILOT_EXCEEDS_COMPONENT_POLICY_LIMITS")
    candidate = FeedbackPolicy(policy_id=policy_id, run_label="REAL_PUBLIC", execution_deadline_ms=deadline_ms,
                               release_floor_ms=deadline_ms + 1000, body_bytes=policy.body_bytes)
    return candidate, {"scope": "SIX_SAMPLE_ENGINEERING_ESTIMATE_NOT_PUBLIC_ADMISSION",
        "sample_count": 6, "maximum_observed_worker_ns": maximum,
        "selection_rule": "ceil_seconds(1.5*max_ns+2s), minimum 5s deadline; floor=deadline+1s; same byte bucket",
        "network_timing_measured": False, "p99_established": False, "calibrated_public_policy": False}
