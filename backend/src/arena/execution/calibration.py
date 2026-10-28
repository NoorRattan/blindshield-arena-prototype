"""Finite workload selection, never a statistical p99/security certification."""

import math

from arena.contracts.transport_profile import FeedbackPolicy
from .pilot import WorkerSample


def zero_failure_upper_bound(n, alpha=0.05):
    """One-sided exact bound for ZERO failures, conditional on iid Bernoulli trials."""
    if type(n) is not int or n <= 0 or not 0 < alpha < 1:
        raise ValueError("INVALID_BINOMIAL_BOUND_INPUT")
    return -math.expm1(math.log(alpha) / n)


def select_workload_policy(samples, policy):
    samples = [WorkerSample.model_validate(s.model_dump() if isinstance(s, WorkerSample) else s) for s in samples]
    policy = FeedbackPolicy.model_validate(policy.model_dump())
    if policy.run_label != "REAL_PUBLIC" or len(samples) != 24 or sorted(s.sample_index for s in samples) != list(range(24)):
        raise ValueError("EXACT_24_REAL_SELECTION_SAMPLES_REQUIRED")
    for sample in samples:
        if (sample.lane != sample.sample_index % 3 or sample.body_bytes != policy.body_bytes
            or sample.deadline_ns - sample.admitted_ns != policy.execution_deadline_ms * 1_000_000
            or sample.release_ns - sample.admitted_ns != policy.release_floor_ms * 1_000_000):
            raise ValueError("SELECTION_SAMPLE_POLICY_MISMATCH")
    times = sorted(s.authorized_observed_ns - s.admitted_ns for s in samples)
    maximum = times[-1]
    # Nearest-rank empirical p99 of 24 values is the observed maximum. It is NOT
    # a confidence bound on the population p99. Rule is fixed before collection.
    deadline = max(5000, math.ceil((maximum + max(2_000_000_000, maximum // 2)) / 1_000_000_000) * 1000)
    if deadline > 119000:
        raise ValueError("SELECTION_EXCEEDS_EXISTING_POLICY_CAP")
    selected = FeedbackPolicy(policy_id="n06-jbb24-engineering-candidate.v1", run_label="REAL_PUBLIC",
        execution_deadline_ms=deadline, release_floor_ms=deadline+1000, body_bytes=policy.body_bytes)
    return selected, {"scope": "24_RECORD_EMPIRICAL_WORKLOAD_SELECTION_NOT_P99_CERTIFICATION", "samples": 24, "waves": 8,
        "empirical_p99_worker_ns": times[math.ceil(.99 * len(times))-1], "maximum_worker_ns": maximum,
        "selection_rule": "ceil_seconds(max + max(2s, 0.5*max)); min 5s; floor=deadline+1s; unchanged bytes",
        "iid_zero_failure_upper_95_if_assumptions_hold": zero_failure_upper_bound(24),
        "iid_wave_zero_failure_upper_95_if_assumptions_hold": zero_failure_upper_bound(8),
        "iid_assumption_established": False, "p99_certified": False, "calibrated_public_policy": False}
