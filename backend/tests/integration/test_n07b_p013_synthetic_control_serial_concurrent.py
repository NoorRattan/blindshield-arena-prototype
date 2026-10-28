from __future__ import annotations

import copy

import pytest

from arena.contracts.crypto import sha256
from tools.run_n07b_p013_synthetic_control_serial_concurrent import (
    CASES,
    analyze_phases,
    phase_plan,
)


def fixture_phases():
    phases = []
    for scheduled in phase_plan():
        turns = []
        for lane, case in enumerate(CASES):
            for turn_index in range(2):
                executed = case["model_execution"] == "EXECUTED"
                turns.append(
                    {
                        "lane": lane,
                        "session_id_sha256": sha256(f"session-{lane}".encode()),
                        "record_id_sha256": sha256(case["record_id"].encode()),
                        "prompt_sha256": sha256(case["text"].encode()),
                        "payload_reference_sha256": sha256(f"ref-{scheduled['block']}-{lane}".encode()),
                        "turn_index": turn_index,
                        "turn_id_sha256": sha256(
                            f"turn-{scheduled['block']}-{scheduled['arm']}-{lane}-{turn_index}".encode()
                        ),
                        "verdict": case["verdict"],
                        "defense_event_outcome": case["verdict"],
                        "pipeline_disposition": case["disposition"],
                        "integrity": "VALID_WITHIN_PROFILE",
                        "model_execution": case["model_execution"],
                        "controller_latency_us": 1000 + lane * 100 + turn_index * 10,
                        "model_latency_us": 5000 + lane * 100 + turn_index * 10 if executed else None,
                        "model_input_tokens": 16 if executed else None,
                        "model_output_tokens": 8 if executed else None,
                        "model_output_sha256": sha256(f"output-{lane}-{turn_index}".encode()) if executed else None,
                    }
                )
        concurrent = scheduled["arm"] == "CONCURRENT"
        phases.append(
            {
                **scheduled,
                "result": "MEASURED",
                "defense_mode": "INPUT",
                "traffic_label": "SYNTHETIC_MOCK",
                "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M",
                "turns": turns,
                "serial_cli_gather_calls": 2 if not concurrent else None,
                "model_overlap": {
                    "model_trace_count": 4,
                    "cross_lane_overlap_pairs": 1 if concurrent else 0,
                    "max_simultaneous_model_traces": 2 if concurrent else 1,
                },
                "n04_cli": {
                    "run_label": "SYNTHETIC_MOCK",
                    "defense_mode": "INPUT",
                    "real_model": True,
                    "verifier_exit_code": 0,
                    "verifier_status": "PASS_PUBLIC_EVIDENCE",
                    "integrity": "VALID_WITHIN_PROFILE",
                    "turn_openings_verified": 6,
                    "turn_count": 6,
                    "model_dispatches": 4,
                },
            }
        )
    return phases


def test_synthetic_controls_compare_all_three_defense_dispositions():
    result = analyze_phases(fixture_phases())

    assert result["result"] == "SYNTHETIC_REAL_MODEL_SERIAL_CONCURRENT_MECHANISM_CONTROLS_OBSERVED"
    assert result["turn_count"] == 36
    assert result["paired_case_count"] == 18
    assert result["defense_verdict_distribution"] == {"ALLOW": 12, "BLOCK": 12, "SANITIZE": 12}
    assert result["model_dispatch_count"] == 24
    assert result["response_pair_count"] == result["response_match_count"] == 12
    assert result["verdict_match_count"] == 18
    assert result["verdict_drift_count"] == 0
    assert result["all_concurrent_runs_overlapped_two_model_lanes"] is True
    assert result["all_serial_runs_had_no_cross_lane_model_overlap"] is True
    assert result["p013_complete"] is False
    assert result["t019_complete"] is False


def test_synthetic_controls_cannot_be_relabelled_as_real_public_jbb():
    phases = fixture_phases()
    phases[0]["n04_cli"]["run_label"] = "REAL_PUBLIC"

    with pytest.raises(ValueError, match="SYNTHETIC_P013_PHASE_OR_N04_ACCEPTANCE_INVALID"):
        analyze_phases(phases)


def test_concurrent_arm_requires_measured_overlap_of_both_model_lanes():
    phases = fixture_phases()
    concurrent = next(phase for phase in phases if phase["arm"] == "CONCURRENT")
    concurrent["model_overlap"]["cross_lane_overlap_pairs"] = 0

    with pytest.raises(ValueError, match="SYNTHETIC_P013_TWO_LANE_MODEL_OVERLAP_NOT_OBSERVED"):
        analyze_phases(phases)


def test_real_model_response_drift_is_reported_without_hiding_the_sample():
    phases = fixture_phases()
    concurrent = next(phase for phase in phases if phase["block"] == 1 and phase["arm"] == "CONCURRENT")
    target = next(turn for turn in concurrent["turns"] if turn["lane"] == 0 and turn["turn_index"] == 0)
    target["model_output_sha256"] = sha256(b"different output")

    result = analyze_phases(phases)

    assert result["response_pair_count"] == 12
    assert result["response_match_count"] == 11
    assert result["response_drift_count"] == 1
    assert result["verdict_match_count"] == 18


def test_blocked_control_must_not_claim_a_model_response():
    phases = copy.deepcopy(fixture_phases())
    blocked = next(turn for turn in phases[0]["turns"] if turn["lane"] == 1)
    blocked["model_execution"] = "EXECUTED"

    with pytest.raises(ValueError, match="SYNTHETIC_P013_CONTROL_OUTCOME_MISMATCH"):
        analyze_phases(phases)
