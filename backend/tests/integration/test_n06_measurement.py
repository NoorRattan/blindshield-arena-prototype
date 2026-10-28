"""Fixed-vector and failure-accounting tests for finite N06C measurements."""

import copy
import math

import pytest

from arena.execution.calibration import select_workload_policy, zero_failure_upper_bound
from arena.execution.policy import FeedbackPolicy
from arena.measurement.statistics import auc, block_interval, analyze_timing


def samples():
    return [dict(sample_index=i, lane=i%3, admitted_ns=0, authorized_observed_ns=2_000_000_000+i,
        deadline_ns=30_000_000_000, release_ns=31_000_000_000, published_observed_ns=31_000_000_001,
        body_bytes=16384, unpadded_body_bytes=1024, pending_status=202, final_status=200, replay_identical=True) for i in range(24)]


def test_fixed_selection_rule_small_sample_uncertainty_and_failure_rejection():
    policy = FeedbackPolicy(policy_id="bootstrap", run_label="REAL_PUBLIC", execution_deadline_ms=30000,
        release_floor_ms=31000, body_bytes=16384)
    selected, estimate = select_workload_policy(samples(), policy)
    assert (selected.execution_deadline_ms, selected.release_floor_ms, selected.body_bytes) == (5000, 6000, 16384)
    assert estimate["empirical_p99_worker_ns"] == 2_000_000_023
    assert not estimate["p99_certified"] and not estimate["iid_assumption_established"]
    assert math.isclose(zero_failure_upper_bound(24), 1-.05**(1/24))
    assert zero_failure_upper_bound(24) > .11 and zero_failure_upper_bound(299) < .01
    for changed in (samples()[:-1], samples()[1:] + [samples()[1]], [dict(s, final_status=503) for s in samples()]):
        with pytest.raises(ValueError): select_workload_policy(changed, policy)
    for n in (0, -1, True, 1.5):
        with pytest.raises(ValueError): zero_failure_upper_bound(n)


def test_rank_auc_ties_direction_and_strict_samples():
    rows = [dict(label=0, latency_ns=1), dict(label=1, latency_ns=3)]
    assert auc(rows) == 1 and auc(rows, -1) == 0
    assert auc([dict(label=0, latency_ns=2), dict(label=1, latency_ns=2)]) == .5
    for bad in ([rows[0]], [dict(label=True, latency_ns=1)], [dict(label=0, latency_ns=-1)]):
        with pytest.raises(ValueError): auc(bad)
    blocks = [dict(row, campaign=i) for i in range(3) for row in rows]
    assert block_interval(blocks, 1, seed=4, repetitions=100) == [1, 1]
    with pytest.raises(ValueError): block_interval([dict(row, campaign=0) for row in rows], 1, seed=4)


def timing_rows():
    return [dict(arm=arm, phase=phase, campaign=campaign, index=i, label=i%2, latency_ns=(100 if i%2 else 200) if arm.startswith("UNSHAPED") else 1000,
        status=200, body_bytes=4096, early_publication=arm.startswith("UNSHAPED"))
        for arm in ("UNSHAPED_SYNTHETIC_CONTROL", "SHAPED") for phase, count in (("selection", 4), ("validation", 10))
        for campaign in range(count) for i in range(24)]


def test_timing_direction_held_out_gate_and_failures_are_never_filtered():
    rows = timing_rows()
    result = analyze_timing(rows)
    assert result["negative_control_detectable"] and result["result"] == "WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE"
    assert result["arms"]["UNSHAPED_SYNTHETIC_CONTROL"]["direction_frozen_from_selection"] == -1
    assert result["arms"]["SHAPED"]["held_out_timing_auc"] == .5
    changed = copy.deepcopy(rows); changed[-1]["status"] = 503
    result = analyze_timing(changed)
    assert result["result"] == "INCONCLUSIVE_OR_OUTSIDE_ENVELOPE"
    assert result["arms"]["SHAPED"]["transport_or_pipeline_failures"] == 1
    with pytest.raises(ValueError): analyze_timing(rows[:-1])
