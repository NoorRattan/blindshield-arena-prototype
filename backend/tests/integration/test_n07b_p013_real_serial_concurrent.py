import asyncio
import hashlib

import pytest

from tools.run_n07b_p013_real_serial_concurrent import (
    SOURCE_FILES as RUNNER_SOURCE_FILES,
    SerialCliAsyncioProxy,
    analyze_phases,
    phase_plan,
)
from tools.verify_n07b_p013_real_serial_concurrent import (
    SOURCE_FILES as VERIFIER_SOURCE_FILES,
    _recompute_analysis,
    _validate_input_identity,
    _validate_private_results,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _phase(block: int, arm: str, *, drift: bool = False) -> dict:
    turns = []
    for lane in range(3):
        for turn_index in range(2):
            record_hash = _hash(f"record-{lane}-{turn_index}")
            prompt_hash = _hash(f"prompt-{lane}-{turn_index}")
            model_hash = _hash(f"output-{lane}-{turn_index}")
            if drift and arm == "CONCURRENT" and block == 1 and lane == 0 and turn_index == 0:
                model_hash = _hash("output-drift")
            turns.append(
                {
                    "lane": lane,
                    "session_id_sha256": _hash(f"session-{lane}-{block}-{arm}"),
                    "record_id_sha256": record_hash,
                    "prompt_sha256": prompt_hash,
                    "payload_reference_sha256": _hash(f"payload-{lane}-{turn_index}"),
                    "turn_index": turn_index,
                    "turn_id_sha256": _hash(f"turn-{block}-{arm}-{lane}-{turn_index}"),
                    "verdict": "ALLOW",
                    "defense_event_outcome": "ALLOW",
                    "pipeline_disposition": "ALLOWED",
                    "integrity": "VALID_WITHIN_PROFILE",
                    "model_execution": "EXECUTED",
                    "controller_latency_us": 1000 + lane * 100 + turn_index,
                    "model_latency_us": 800 + lane * 100 + turn_index,
                    "model_input_tokens": 20 + turn_index,
                    "model_output_tokens": 10 + lane,
                    "model_output_sha256": model_hash,
                }
            )
    return {
        "block": block,
        "arm": arm,
        "result": "MEASURED",
        "defense_mode": "INPUT",
        "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M",
        "turns": turns,
        "model_overlap": {
            "cross_lane_overlap_pairs": 0 if arm == "SERIAL" else 2,
            "model_trace_count": 6,
            "max_simultaneous_model_traces": 1 if arm == "SERIAL" else 3,
        },
        "serial_cli_gather_calls": 2 if arm == "SERIAL" else None,
        "n04_cli": {
            "run_label": "REAL_PUBLIC",
            "defense_mode": "INPUT",
            "real_model": True,
            "turn_count": 6,
            "model_dispatches": 6,
            "verifier_exit_code": 0,
            "verifier_status": "PASS_PUBLIC_EVIDENCE",
            "integrity": "VALID_WITHIN_PROFILE",
            "turn_openings_verified": 6,
        },
    }


def _phases(*, drift: bool = False) -> list[dict]:
    return [
        _phase(item["block"], item["arm"], drift=drift)
        for item in phase_plan()
    ]


def test_phase_plan_counterbalances_serial_and_concurrent_order():
    assert phase_plan() == [
        {"block": 1, "arm": "SERIAL"},
        {"block": 1, "arm": "CONCURRENT"},
        {"block": 2, "arm": "CONCURRENT"},
        {"block": 2, "arm": "SERIAL"},
        {"block": 3, "arm": "SERIAL"},
        {"block": 3, "arm": "CONCURRENT"},
    ]


def test_analysis_matches_all_inputs_and_reports_response_drift_without_promoting_p013():
    summary = analyze_phases(_phases(drift=True))

    assert summary["phase_count"] == 6
    assert summary["turn_count"] == 36
    assert summary["paired_case_count"] == 18
    assert summary["response_pair_count"] == 18
    assert summary["response_match_count"] == 17
    assert summary["response_drift_count"] == 1
    assert summary["verdict_drift_count"] == 0
    assert summary["all_serial_runs_showed_no_cross_lane_model_overlap"] is True
    assert summary["all_concurrent_runs_showed_cross_lane_model_overlap"] is True
    assert summary["p013_complete"] is False
    assert summary["p011_complete"] is False


def test_analysis_fails_closed_when_case_set_or_expected_overlap_is_missing():
    phases = _phases()
    phases[1]["turns"].pop()
    with pytest.raises(ValueError, match="P013_PHASE_INVALID_OR_N04_VERIFICATION_FAILED"):
        analyze_phases(phases)

    phases = _phases()
    phases[1]["model_overlap"]["cross_lane_overlap_pairs"] = 0
    with pytest.raises(ValueError, match="P013_CONCURRENT_THREE_LANE_OVERLAP_NOT_OBSERVED"):
        analyze_phases(phases)

    phases = _phases()
    phases[1]["model_overlap"]["max_simultaneous_model_traces"] = 2
    with pytest.raises(ValueError, match="P013_CONCURRENT_THREE_LANE_OVERLAP_NOT_OBSERVED"):
        analyze_phases(phases)

    phases = _phases()
    phases[0]["n04_cli"]["model_dispatches"] = 0
    with pytest.raises(ValueError, match="P013_PHASE_INVALID_OR_N04_VERIFICATION_FAILED"):
        analyze_phases(phases)

    phases = _phases()
    for phase in phases:
        for turn in phase["turns"]:
            turn.update(
                model_output_sha256=None,
                model_execution="NOT_EVALUATED",
                model_latency_us=None,
                model_input_tokens=None,
                model_output_tokens=None,
            )
        phase["n04_cli"]["model_dispatches"] = 0
        phase["model_overlap"] = {
            "cross_lane_overlap_pairs": 0,
            "model_trace_count": 0,
            "max_simultaneous_model_traces": 0,
        }
    with pytest.raises(ValueError, match="P013_PHASE_INVALID_OR_N04_VERIFICATION_FAILED"):
        analyze_phases(phases)


def test_token_matches_exclude_paired_pre_inference_blocks():
    phases = _phases()
    for phase in phases:
        blocked = next(
            turn for turn in phase["turns"] if turn["lane"] == 2 and turn["turn_index"] == 1
        )
        blocked.update(
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
        phase["model_overlap"]["model_trace_count"] = 5

    summary = analyze_phases(phases)
    assert summary["response_pair_count"] == 15
    assert summary["model_token_pair_count"] == 15
    assert summary["input_token_match_count"] == 15
    assert summary["output_token_match_count"] == 15
    assert all(
        row["input_tokens_match"] is None and row["output_tokens_match"] is None
        for row in summary["paired_rows"]
        if row["lane"] == 2 and row["turn_index"] == 1
    )


def test_analysis_refuses_no_paired_real_model_outputs():
    phases = _phases()
    for phase in phases:
        execute_turn_index = 0 if phase["arm"] == "SERIAL" else 1
        for turn in phase["turns"]:
            if turn["turn_index"] == execute_turn_index:
                continue
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
        phase["n04_cli"]["model_dispatches"] = 3
        phase["model_overlap"]["model_trace_count"] = 3

    with pytest.raises(ValueError, match="P013_NO_PAIRED_REAL_MODEL_RESPONSES"):
        analyze_phases(phases)


def test_independent_verifier_recomputes_analysis_and_binds_private_n04_rows():
    assert set(RUNNER_SOURCE_FILES) == set(VERIFIER_SOURCE_FILES)
    phases = _phases(drift=True)
    expected = _recompute_analysis(phases)
    assert expected == analyze_phases(phases)

    tampered = _phases(drift=True)
    tampered[0]["turns"][0]["verdict"] = "BLOCK"
    with pytest.raises(ValueError, match="P013_TURN_RESULT_INVALID"):
        _recompute_analysis(tampered)

    phase = phases[0]
    results = [None] * 6
    for turn in phase["turns"]:
        results[turn["turn_index"] * 3 + turn["lane"]] = {
            "defense_mode": "INPUT",
            "pipeline_disposition": turn["pipeline_disposition"],
            "model_execution": turn["model_execution"],
            "integrity": turn["integrity"],
        }
    summary = {"execution_lock_sha256": _hash("lock"), "results": results}
    _validate_private_results(phase=phase, summary=summary, lock_sha256=_hash("lock"))

    summary["execution_lock_sha256"] = _hash("other-lock")
    with pytest.raises(ValueError, match="PRIVATE_N04_EXECUTION_LOCK_MISMATCH"):
        _validate_private_results(phase=phase, summary=summary, lock_sha256=_hash("lock"))

    summary["execution_lock_sha256"] = _hash("lock")
    summary["results"][0]["pipeline_disposition"] = "BLOCKED_BY_DEFENSE"
    with pytest.raises(ValueError, match="PRIVATE_N04_RESULT_ROW_MISMATCH"):
        _validate_private_results(phase=phase, summary=summary, lock_sha256=_hash("lock"))


def test_independent_verifier_binds_public_case_hashes_to_private_input_opening():
    provenance = {
        "source_id": "JBB-Behaviors",
        "immutable_revision": "886acc352a31533ffbcf4ef22c744658688086fc",
        "source_sha256": _hash("source"),
        "record_id": "record-0-0",
        "license_id": "MIT",
        "run_label": "REAL_PUBLIC",
    }
    turn = {
        "record_id_sha256": _hash("record-0-0"),
        "prompt_sha256": _hash("prompt-0-0"),
        "payload_reference_sha256": _hash("payload-ref"),
        "turn_id_sha256": _hash("turn-id"),
        "session_id_sha256": _hash("session-id"),
        "turn_index": 0,
    }
    opening = {
        "original_utf8_base64": "cHJvbXB0LTAtMA==",
        "provenance": provenance,
        "schema_version": "arena-n04-input.v1",
        "turn_id": "turn-id",
        "session_id": "session-id",
        "turn_index": 0,
    }
    _validate_input_identity(
        turn=turn,
        opening=opening,
        payload_ref="payload-ref",
        payload_text="prompt-0-0",
        provenance=provenance,
    )

    for field, value in (
        ("record_id_sha256", _hash("substituted-record")),
        ("prompt_sha256", _hash("substituted-prompt")),
        ("payload_reference_sha256", _hash("substituted-payload")),
    ):
        tampered = {**turn, field: value}
        with pytest.raises(ValueError, match="PRIVATE_N04_INPUT_OPENING_MISMATCH"):
            _validate_input_identity(
                turn=tampered,
                opening=opening,
                payload_ref="payload-ref",
                payload_text="prompt-0-0",
                provenance=provenance,
            )

    altered_provenance = {**provenance, "source_id": "OTHER"}
    with pytest.raises(ValueError, match="PRIVATE_N04_INPUT_OPENING_MISMATCH"):
        _validate_input_identity(
            turn=turn,
            opening=opening,
            payload_ref="payload-ref",
            payload_text="prompt-0-0",
            provenance=altered_provenance,
        )


def test_serial_cli_proxy_runs_each_three_lane_wave_in_order():
    proxy = SerialCliAsyncioProxy(asyncio)
    events = []

    async def item(index):
        events.append(("start", index))
        await asyncio.sleep(0)
        events.append(("end", index))
        return index

    async def run_wave():
        return await proxy.gather(*(item(i) for i in range(3)), return_exceptions=True)

    assert asyncio.run(run_wave()) == [0, 1, 2]
    assert proxy.gather_calls == 1
    assert events == [
        ("start", 0), ("end", 0),
        ("start", 1), ("end", 1),
        ("start", 2), ("end", 2),
    ]


def test_serial_cli_proxy_rejects_unexpected_wave_shape():
    proxy = SerialCliAsyncioProxy(asyncio)
    async def run_wave():
        await proxy.gather(object(), object(), return_exceptions=True)

    with pytest.raises(RuntimeError, match="UNEXPECTED_SERIAL_CLI_GATHER_SHAPE"):
        asyncio.run(run_wave())


def test_serial_cli_proxy_matches_n04_default_exception_policy():
    proxy = SerialCliAsyncioProxy(asyncio)
    events = []

    async def item(index):
        events.append(("start", index))
        await asyncio.sleep(0)
        events.append(("end", index))
        return index

    async def run_wave():
        return await proxy.gather(*(item(i) for i in range(3)))

    assert asyncio.run(run_wave()) == [0, 1, 2]
    assert events == [
        ("start", 0), ("end", 0),
        ("start", 1), ("end", 1),
        ("start", 2), ("end", 2),
    ]


def test_serial_cli_proxy_propagates_default_policy_failure_and_does_not_start_later_calls():
    proxy = SerialCliAsyncioProxy(asyncio)
    events = []

    async def ok(index):
        events.append(("start", index))
        await asyncio.sleep(0)
        events.append(("end", index))

    async def fail():
        events.append(("fail", 1))
        raise RuntimeError("CONTROLLED_TEST_FAILURE")

    async def run_wave():
        await proxy.gather(ok(0), fail(), ok(2))

    with pytest.raises(RuntimeError, match="CONTROLLED_TEST_FAILURE"):
        asyncio.run(run_wave())
    assert events == [("start", 0), ("end", 0), ("fail", 1)]
