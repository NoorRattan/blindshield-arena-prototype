from __future__ import annotations

import pytest

from tools.run_n07b_resource_ram_pid_pressure import (
    PID_PRESSURE_TASKS,
    RAM_MINIMUM_RISE_BYTES,
    analyze_phases,
    phase_plan,
)


def _phase(scheduled: dict, *, pressure: dict | None = None) -> dict:
    turns = []
    for lane in range(3):
        for turn_index in range(2):
            prompt_hash = f"{lane * 2 + turn_index + 1:064x}"
            turns.append(
                {
                    "lane": lane,
                    "record_id_sha256": f"{lane * 2 + turn_index + 101:064x}",
                    "prompt_sha256": prompt_hash,
                    "turn_index": turn_index,
                    "verdict": "ALLOW",
                    "defense_event_outcome": "ALLOW",
                    "pipeline_disposition": "ALLOWED",
                    "model_execution": "EXECUTED",
                    "controller_latency_us": 100 + turn_index,
                    "model_latency_us": 80 + lane,
                    "model_input_tokens": 7,
                    "model_output_tokens": 3,
                    "model_output_sha256": f"{lane * 2 + turn_index + 201:064x}",
                }
            )
    return {
        **scheduled,
        "result": "MEASURED",
        "turns": turns,
        "resource_pressure": pressure,
        "model_cgroup_delta": {
            str(lane): {"memory_events_delta": {"oom": 0, "oom_kill": 0}}
            for lane in range(3)
        },
        "n04_cli": {
            "run_label": "REAL_PUBLIC",
            "defense_mode": "INPUT",
            "real_model": True,
            "three_lane_acceptance": False,
            "n05_baseline_mechanisms_delivered": True,
            "turn_count": 6,
            "model_dispatches": 6,
            "verifier_exit_code": 0,
            "verifier_status": "PASS_PUBLIC_EVIDENCE",
        },
    }


def _valid_observation() -> list[dict]:
    phases = []
    for scheduled in phase_plan():
        condition = scheduled["condition"]
        pressure = None
        if condition == "RAM_PRESSURE":
            pressure = {
                "kind": "VM_SHARED_RESIDENT_RAM_CGROUP",
                "cleanup_completed": True,
                "safety_floor_crossed": False,
                "oom_killed": False,
                "minimum_mem_available_bytes": 9_000_000_000,
                "minimum_required_available_bytes": 8_500_000_000,
                "allocation_cgroup_rise_bytes": RAM_MINIMUM_RISE_BYTES,
                "allocation_cgroup_current_before_bytes": 1_048_576,
                "allocation_cgroup_current_after_bytes": 1_048_576 + RAM_MINIMUM_RISE_BYTES,
                "window_resource_current_bytes_after": 1_048_576 + RAM_MINIMUM_RISE_BYTES,
                "allocation_memory_events_delta": {"oom": 0, "oom_kill": 0},
                "window_cgroup_delta": {
                    "memory_events_delta": {"oom": 0, "oom_kill": 0}
                },
                "mem_available_after_bytes": 9_000_000_000,
                "pressure_released_for_headroom": False,
                "stressor_exit_code": 0,
            }
        elif condition == "PID_PRESSURE":
            pressure = {
                "kind": "SELECTED_MODEL_LANE_PIDS_CGROUP_OCCUPANCY",
                "cleanup_completed": True,
                "same_model_cell_cgroup": True,
                "children_idle": True,
                "model_cell_container_matches_window_end": True,
                "pids_current_delta": PID_PRESSURE_TASKS,
                "pids_current_before": 10,
                "pids_current_after_start": 74,
                "pid_cgroup_limit": 128,
                "window_cgroup_delta": {"pids_current_after": 75},
                "pids_current_after_cleanup": 11,
                "all_pool_pids_absent_after_cleanup": True,
                "container_removed_after_window_end": False,
                "cleanup_method": "EXACT_RECORDED_PID_SET_REAPED",
            }
        phases.append(_phase(scheduled, pressure=pressure))
    return phases


def test_phase_plan_counterbalances_baseline_ram_and_pid_arms() -> None:
    plan = phase_plan()
    assert len(plan) == 9
    for block in range(1, 4):
        phases = [item for item in plan if item["block"] == block]
        assert {item["condition"] for item in phases} == {
            "BASELINE",
            "RAM_PRESSURE",
            "PID_PRESSURE",
        }
        assert len({item["stress_lane"] for item in phases if item["condition"] != "BASELINE"}) == 1


def test_analysis_reconciles_pressure_pair_counts_and_limits_claims() -> None:
    result = analyze_phases(_valid_observation())
    assert result["result"] == "RAM_PID_PRESSURE_PAIRED_OBSERVED"
    assert result["phase_count"] == 9
    assert result["turn_count"] == 54
    assert result["baseline_to_resource_pair_count"] == 36
    assert result["verdict_distribution"] == {"ALLOW": 54}
    assert result["varied_defense_outcomes_observed"] is False
    assert result["defense_outcome_coverage"] == "SINGLE_OUTCOME_ALLOW"
    assert result["defense_outcome_drift_count"] == 0
    assert result["ram_pressure_observed"] is True
    assert result["pid_pressure_observed_in_selected_model_cgroup"] is True
    assert result["fairness_established"] is False
    assert result["p011_complete"] is False
    assert result["p013_complete"] is False


def test_analysis_rejects_pid_processes_outside_selected_model_cgroup() -> None:
    phases = _valid_observation()
    for phase in phases:
        if phase["condition"] == "PID_PRESSURE":
            phase["resource_pressure"]["same_model_cell_cgroup"] = False
            break
    with pytest.raises(ValueError, match="PID_PRESSURE_ASSERTION_FAILED"):
        analyze_phases(phases)


def test_analysis_preserves_real_outcome_drift_without_calling_it_acceptance() -> None:
    phases = _valid_observation()
    for phase in phases:
        if phase["condition"] == "RAM_PRESSURE":
            turn = phase["turns"][0]
            turn.update(
                verdict="BLOCK",
                defense_event_outcome="BLOCK",
                pipeline_disposition="BLOCKED_BY_DEFENSE",
                model_execution="NOT_EVALUATED",
                model_latency_us=None,
                model_input_tokens=None,
                model_output_tokens=None,
                model_output_sha256=None,
            )
            phase["n04_cli"]["model_dispatches"] = 5
            break
    result = analyze_phases(phases)
    assert result["result"] == "OUTCOME_DRIFT_OBSERVED"
    assert result["defense_outcome_drift_count"] == 1
    assert result["p011_complete"] is False


def test_analysis_rejects_pressure_that_does_not_persist_through_the_turn_window() -> None:
    phases = _valid_observation()
    for phase in phases:
        if phase["condition"] == "RAM_PRESSURE":
            phase["resource_pressure"]["window_resource_current_bytes_after"] = 0
            break
    with pytest.raises(ValueError, match="RAM_PRESSURE_ASSERTION_FAILED"):
        analyze_phases(phases)

    phases = _valid_observation()
    for phase in phases:
        if phase["condition"] == "PID_PRESSURE":
            phase["resource_pressure"]["window_cgroup_delta"]["pids_current_after"] = 20
            break
    with pytest.raises(ValueError, match="PID_PRESSURE_ASSERTION_FAILED"):
        analyze_phases(phases)


def test_analysis_rejects_model_cgroup_oom_events() -> None:
    phases = _valid_observation()
    phases[0]["model_cgroup_delta"]["1"]["memory_events_delta"]["oom_kill"] = 1
    with pytest.raises(ValueError, match="MODEL_CGROUP_OOM_EVENT_OBSERVED_OR_UNAVAILABLE"):
        analyze_phases(phases)


def test_analysis_accepts_cell_removal_only_after_pressure_was_captured_at_window_end() -> None:
    phases = _valid_observation()
    for phase in phases:
        if phase["condition"] == "PID_PRESSURE":
            pressure = phase["resource_pressure"]
            pressure["cleanup_method"] = "N05_CELL_REMOVED_AFTER_WINDOW_CAPTURE"
            pressure["container_removed_after_window_end"] = True
            pressure["pids_current_after_cleanup"] = None
    result = analyze_phases(phases)
    assert result["pid_pressure_observed_in_selected_model_cgroup"] is True

    for phase in phases:
        if phase["condition"] == "PID_PRESSURE":
            phase["resource_pressure"]["model_cell_container_matches_window_end"] = False
            break
    with pytest.raises(ValueError, match="PID_PRESSURE_ASSERTION_FAILED"):
        analyze_phases(phases)

