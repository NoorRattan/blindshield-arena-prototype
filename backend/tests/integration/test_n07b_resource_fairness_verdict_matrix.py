from __future__ import annotations

import hashlib

import pytest

from tools.run_n07b_resource_fairness_verdict_matrix import (
    analyze_phases,
    measured_model_traces,
    model_overlap_summary,
    phase_plan,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _measured_phases():
    phases = []
    for scheduled in phase_plan():
        turns = []
        for lane in range(3):
            for record_index in range(2):
                record_id = f"lane-{lane}-record-{record_index}"
                prompt = f"public-jbb-{lane}-{record_index}"
                stressed_here = (
                    scheduled["condition"] == "CPU_LOAD"
                    and scheduled["stress_lane"] == lane
                )
                baseline_latency = 1000 + lane * 100 + record_index * 10
                latency = baseline_latency + (50 if stressed_here else 0)
                turns.append(
                    {
                        "lane": lane,
                        "record_id_sha256": _sha(record_id),
                        "prompt_sha256": _sha(prompt),
                        "payload_reference_sha256": _sha("ref-" + record_id),
                        "turn_index": record_index,
                        "turn_id_sha256": _sha(scheduled["phase"] + record_id),
                        "verdict": "ALLOW",
                        "defense_event_outcome": "ALLOW",
                        "pipeline_disposition": "ALLOWED",
                        "model_execution": "EXECUTED",
                        "controller_latency_us": latency,
                        "model_latency_us": latency - 300,
                        "model_input_tokens": 10,
                        "model_output_tokens": 8,
                        "model_output_sha256": _sha(scheduled["phase"] + prompt),
                    }
                )
        phases.append(
            {
                **scheduled,
                "result": "MEASURED",
                "turns": turns,
                "burner": {"load_detected": True}
                if scheduled["condition"] == "CPU_LOAD"
                else None,
            }
        )
    return phases


def test_phase_plan_counterbalances_each_lane_across_three_blocks():
    plan = phase_plan()
    assert len(plan) == 15
    assert [item["stress_lane"] for item in plan if item["condition"] == "CPU_LOAD"] == [
        0, 1, 2, 1, 2, 0, 2, 0, 1
    ]
    assert [sum(item["stress_lane"] == lane for item in plan) for lane in range(3)] == [
        3, 3, 3
    ]


def test_analysis_pairs_each_loaded_turn_to_two_same_block_baselines():
    summary = analyze_phases(_measured_phases())
    assert summary["result"] == "CPU_VERDICT_LATENCY_PAIRED"
    assert summary["turn_count"] == 90
    assert summary["paired_latency_observation_count"] == 54
    assert summary["verdicts_stable_across_matched_trials"] is True
    assert summary["verdict_drift_case_count"] == 0
    assert summary["stressed_lane_pair_count"] == 18
    assert summary["stressed_lane_pairs_with_latency_change_under_10_percent"] == 18
    assert summary["p011_complete"] is False
    assert summary["p013_complete"] is False


def test_analysis_records_verdict_drift_without_calling_the_matrix_passed():
    phases = _measured_phases()
    loaded = next(item for item in phases if item["condition"] == "CPU_LOAD")
    changed = loaded["turns"][0]
    changed["verdict"] = "BLOCK"
    changed["defense_event_outcome"] = "BLOCK"
    changed["pipeline_disposition"] = "BLOCKED_BY_DEFENSE"
    summary = analyze_phases(phases)
    assert summary["result"] == "INCONCLUSIVE_OR_VERDICT_DRIFT"
    assert summary["verdicts_stable_across_matched_trials"] is False
    assert summary["verdict_drift_case_count"] == 1


def test_analysis_rejects_event_verdict_mismatch():
    phases = _measured_phases()
    phases[0]["turns"][0]["defense_event_outcome"] = "BLOCK"
    with pytest.raises(ValueError, match="RESOURCE_MATRIX_TURN_PAIR_INVALID"):
        analyze_phases(phases)


def test_analysis_rejects_duplicate_case_keys_in_a_phase():
    phases = _measured_phases()
    phases[1]["turns"][1] = dict(phases[1]["turns"][0])
    with pytest.raises(ValueError, match="RESOURCE_MATRIX_DUPLICATE_CASE_KEY"):
        analyze_phases(phases)


def test_measured_model_traces_exclude_n05_startup_conformance_probes():
    turns = [
        {
            "turn_id_sha256": _sha("turn-0"),
            "lane": 0,
            "model_execution": "EXECUTED",
        },
        {
            "turn_id_sha256": _sha("turn-1"),
            "lane": 1,
            "model_execution": "EXECUTED",
        },
    ]
    traces = [
        {"turn_id": "startup-probe", "lane": 0, "begin_ns": 1, "end_ns": 2},
        {"turn_id": "turn-0", "lane": 0, "begin_ns": 10, "end_ns": 30},
        {"turn_id": "turn-1", "lane": 1, "begin_ns": 20, "end_ns": 40},
    ]
    selected = measured_model_traces(turns, traces)
    assert {item["turn_id"] for item in selected} == {"turn-0", "turn-1"}
    assert model_overlap_summary(selected)["cross_lane_overlap_pairs"] == 1


def test_overlap_summary_uses_actual_intersecting_cross_lane_traces():
    summary = model_overlap_summary(
        [
            {"lane": 0, "begin_ns": 10, "end_ns": 40},
            {"lane": 1, "begin_ns": 20, "end_ns": 50},
            {"lane": 2, "begin_ns": 60, "end_ns": 70},
        ]
    )
    assert summary == {
        "model_trace_count": 3,
        "cross_lane_overlap_pairs": 1,
        "max_simultaneous_model_traces": 2,
        "overlap_observed": True,
    }
