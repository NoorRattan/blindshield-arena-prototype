"""Independently reconcile a bounded N07B real-model comparison receipt."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import statistics
import sqlite3
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
SCOPE = "N07B_BOUNDED_REAL_MODEL_SERIAL_CONCURRENT_INPUT_PATH_COMPARISON"
LANES = 3
TURNS_PER_RUN = 6
BLOCK_ORDER = (
    (("SERIAL", "CONCURRENT"), ("CONCURRENT", "SERIAL"), ("SERIAL", "CONCURRENT"))
)
SOURCE_FILES = (
    "tools/run_n07b_p013_real_serial_concurrent.py",
    "tools/run_n07b_resource_fairness_verdict_matrix.py",
    "tests/integration/test_n07b_p013_real_serial_concurrent.py",
    "tools/run_n07b_resource_fairness_probe.py",
    "tools/verify_n07b_p013_real_serial_concurrent.py",
    "src/arena/integration/cli.py",
    "src/arena/integration/controller.py",
    "src/arena/integration/lanes.py",
    "src/arena/integration/runtime.py",
    "src/arena/adapters/llama_adapter.py",
    "infra/cells/defense.py",
)
sys.path.insert(0, str(ROOT))

from arena.contracts.api import TargetResponse  # noqa: E402
from arena.contracts.common import Context  # noqa: E402
from arena.contracts.crypto import sha256  # noqa: E402
from arena.contracts.evidence import Event  # noqa: E402
from arena.contracts.jsonwire import load_wire  # noqa: E402
from arena.integration.corpus import PreparedPublicCorpus  # noqa: E402
from arena.integration.lanes import LaneAdmission  # noqa: E402
from arena.integration.runtime import runtime_source_hashes  # noqa: E402
from arena.integration.types import AdmissionLock  # noqa: E402
from arena.verifier.archive import safe_extract_archive  # noqa: E402
from arena.verifier.openings import verify_n04_openings  # noqa: E402
from arena.verifier.replay import replay_and_decrypt_artifacts  # noqa: E402


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def source_hashes() -> dict[str, str]:
    return {name: digest_file(ROOT / name) for name in SOURCE_FILES}


def _inside_artifacts(path: Path) -> bool:
    try:
        path.resolve().relative_to(ARTIFACTS.resolve())
        return True
    except ValueError:
        return False


def _phase_plan() -> list[dict[str, Any]]:
    return [
        {"block": block, "arm": arm}
        for block, order in enumerate(BLOCK_ORDER, start=1)
        for arm in order
    ]


def _turn_key(turn: dict[str, Any]) -> tuple[int, str, str, int]:
    return (
        turn["lane"],
        turn["record_id_sha256"],
        turn["prompt_sha256"],
        turn["turn_index"],
    )


def _overlap_summary(traces: list[dict[str, Any]]) -> dict[str, int | bool]:
    if any(
        type(item.get("lane")) is not int
        or type(item.get("begin_ns")) is not int
        or type(item.get("end_ns")) is not int
        or item["end_ns"] <= item["begin_ns"]
        for item in traces
    ):
        raise ValueError("PRIVATE_MODEL_TRACE_INTERVAL_INVALID")
    max_active = 0
    overlap_pairs = 0
    for item in traces:
        max_active = max(
            max_active,
            sum(
                other["begin_ns"] < item["end_ns"]
                and item["begin_ns"] < other["end_ns"]
                for other in traces
            ),
        )
    for index, left in enumerate(traces):
        for right in traces[index + 1 :]:
            if (
                left["lane"] != right["lane"]
                and max(left["begin_ns"], right["begin_ns"])
                < min(left["end_ns"], right["end_ns"])
            ):
                overlap_pairs += 1
    return {
        "model_trace_count": len(traces),
        "cross_lane_overlap_pairs": overlap_pairs,
        "max_simultaneous_model_traces": max_active,
        "overlap_observed": overlap_pairs > 0,
    }


def _select_private_traces(
    turns: list[dict[str, Any]], traces: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    expected = {
        turn["turn_id_sha256"]: turn
        for turn in turns
        if turn.get("model_execution") == "EXECUTED"
    }
    selected: dict[str, dict[str, Any]] = {}
    for trace in traces:
        turn_id = trace.get("turn_id")
        if not isinstance(turn_id, str):
            continue
        try:
            trace_key = sha256(turn_id.encode("ascii"))
        except UnicodeEncodeError:
            continue
        if trace_key not in expected:
            continue
        if trace_key in selected or trace.get("lane") != expected[trace_key]["lane"]:
            raise ValueError("PRIVATE_MODEL_TRACE_BINDING_INVALID")
        if trace.get("execution") != "EXECUTED":
            raise ValueError("PRIVATE_MODEL_TRACE_EXECUTION_INVALID")
        selected[trace_key] = trace
    if set(selected) != set(expected):
        raise ValueError("PRIVATE_MODEL_TRACE_SET_MISMATCH")
    return list(selected.values())


def _validate_private_results(
    *, phase: dict[str, Any], summary: dict[str, Any], lock_sha256: str
) -> None:
    if summary.get("execution_lock_sha256") != lock_sha256:
        raise ValueError("PRIVATE_N04_EXECUTION_LOCK_MISMATCH")
    results = summary.get("results")
    turns = phase.get("turns")
    if not isinstance(results, list) or len(results) != TURNS_PER_RUN or not isinstance(turns, list):
        raise ValueError("PRIVATE_N04_RESULTS_INVALID")
    for turn in turns:
        lane, turn_index = turn.get("lane"), turn.get("turn_index")
        if type(lane) is not int or type(turn_index) is not int:
            raise ValueError("PRIVATE_N04_RESULT_INDEX_INVALID")
        index = turn_index * LANES + lane
        if lane not in range(LANES) or turn_index not in range(2) or index >= len(results):
            raise ValueError("PRIVATE_N04_RESULT_INDEX_INVALID")
        result = results[index]
        if (
            result.get("defense_mode") != phase.get("n04_cli", {}).get("defense_mode")
            or result.get("pipeline_disposition") != turn.get("pipeline_disposition")
            or result.get("model_execution") != turn.get("model_execution")
            or result.get("integrity") != turn.get("integrity")
        ):
            raise ValueError("PRIVATE_N04_RESULT_ROW_MISMATCH")


def _validate_input_identity(
    *,
    turn: dict[str, Any],
    opening: dict[str, Any],
    payload_ref: str,
    payload_text: str,
    provenance: dict[str, Any],
) -> None:
    try:
        original = base64.b64decode(opening["original_utf8_base64"], validate=True)
        record_id = opening["provenance"]["record_id"]
        valid = (
            opening.get("schema_version") == "arena-n04-input.v1"
            and sha256(original) == turn["prompt_sha256"]
            and sha256(record_id.encode("utf-8")) == turn["record_id_sha256"]
            and sha256(payload_ref.encode("utf-8")) == turn["payload_reference_sha256"]
            and original == payload_text.encode("utf-8")
            and opening["provenance"] == provenance
            and sha256(opening["turn_id"].encode("ascii")) == turn["turn_id_sha256"]
            and sha256(opening["session_id"].encode("ascii")) == turn["session_id_sha256"]
            and opening["turn_index"] == turn["turn_index"]
        )
    except Exception as exc:
        raise ValueError("PRIVATE_N04_INPUT_OPENING_MISMATCH") from exc
    if not valid:
        raise ValueError("PRIVATE_N04_INPUT_OPENING_MISMATCH")


def _rerun_private_verifier(private_run: Path, trust: dict[str, Any]) -> None:
    required = (
        "domain_id",
        "experiment_id",
        "epoch",
        "manifest_digest",
        "recorder_key_id",
        "witness_key_id",
        "broker_actor",
        "defense_mode",
    )
    if any(not trust.get(name) for name in required) or trust["defense_mode"] != "INPUT":
        raise ValueError("PRIVATE_N04_TRUST_CONTEXT_INVALID")
    command = [
        sys.executable,
        "-m",
        "arena.verifier.cli",
        "--bundle",
        str(private_run / "public-evidence.zip"),
        "--recorder-key",
        str(private_run / "recorder-public.hex"),
        "--witness-key",
        str(private_run / "witness-public.hex"),
        "--domain-id",
        trust["domain_id"],
        "--experiment-id",
        trust["experiment_id"],
        "--epoch",
        str(trust["epoch"]),
        "--manifest-digest",
        trust["manifest_digest"],
        "--recorder-key-id",
        trust["recorder_key_id"],
        "--witness-key-id",
        trust["witness_key_id"],
        "--defense-mode",
        "INPUT",
        "--broker-actor",
        trust["broker_actor"],
        "--keys-json",
        str(private_run / "private-replay-keys.json"),
    ]
    try:
        verified = subprocess.run(
            command, cwd=ROOT, capture_output=True, timeout=90, check=False
        )
        result = json.loads(verified.stdout)
    except Exception as exc:
        raise ValueError("PRIVATE_N04_VERIFIER_RERUN_FAILED") from exc
    diagnostics = result.get("diagnostics", {})
    if (
        verified.returncode != 0
        or result.get("status") != "PASS_PUBLIC_EVIDENCE"
        or diagnostics.get("integrity") != "VALID_WITHIN_PROFILE"
        or diagnostics.get("turn_openings_verified") != TURNS_PER_RUN
    ):
        raise ValueError("PRIVATE_N04_VERIFIER_RERUN_REJECTED")


def _verify_private_events_and_model(
    *,
    private_run: Path,
    phase: dict[str, Any],
    trust: dict[str, Any],
    public_corpus: PreparedPublicCorpus,
) -> None:
    from arena.contracts.api import DefenseDecision

    key_data = json.loads((private_run / "private-replay-keys.json").read_text(encoding="utf-8"))
    keys = {
        key: bytes.fromhex(value["key"] if isinstance(value, dict) else value)
        for key, value in key_data.items()
    }
    classifications = {
        key: value["classification"]
        for key, value in key_data.items()
        if isinstance(value, dict)
    }
    context = Context(
        domain_id=trust["domain_id"],
        experiment_id=trust["experiment_id"],
        epoch=trust["epoch"],
    )
    with tempfile.TemporaryDirectory(dir=ARTIFACTS, prefix="n07b-p013-verify-") as temp:
        bundle = Path(temp)
        safe_extract_archive(private_run / "public-evidence.zip", bundle)
        artifact_dir = bundle / "artifacts"
        if {path.stem for path in artifact_dir.iterdir()} != set(keys):
            raise ValueError("PRIVATE_ARTIFACT_KEY_COVERAGE_MISMATCH")
        decrypted = replay_and_decrypt_artifacts(
            artifacts_dir=artifact_dir,
            artifact_keys=keys,
            context=context,
            classifications=classifications,
        )
        if verify_n04_openings(bundle, decrypted, "INPUT") != TURNS_PER_RUN:
            raise ValueError("PRIVATE_N04_OPENING_COUNT_MISMATCH")
        events = [
            load_wire(Event, line.encode("utf-8"))
            for line in (bundle / "events.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        database = private_run / "broker.sqlite3"
        if not database.is_file():
            raise ValueError("PRIVATE_N04_DATABASE_MISSING")
        connection = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            for turn in phase["turns"]:
                owned = [
                    event
                    for event in events
                    if event.turn_id is not None
                    and sha256(event.turn_id.encode("ascii")) == turn["turn_id_sha256"]
                ]
                if any(
                    event.turn_index != turn["turn_index"]
                    or event.session_id is None
                    or sha256(event.session_id.encode("ascii")) != turn["session_id_sha256"]
                    for event in owned
                ):
                    raise ValueError("PRIVATE_N04_EVENT_CONTEXT_MISMATCH")
                defense_events = [event for event in owned if event.event_type == "DEFENSE_RESULT"]
                feedback_events = [event for event in owned if event.event_type == "FEEDBACK_AUTHORIZED"]
                if (
                    len(defense_events) != 1
                    or len(feedback_events) != 1
                    or defense_events[0].outcome_code != turn["defense_event_outcome"]
                    or defense_events[0].outcome_code != turn["verdict"]
                ):
                    raise ValueError("PRIVATE_N04_DEFENSE_EVENT_MISMATCH")
                defense_ref = defense_events[0].artifact_ciphertext_refs[0].artifact_id.lower()
                private_defense = json.loads(decrypted[defense_ref])
                decision = DefenseDecision.model_validate(private_defense["decision"])
                if decision.verdict != turn["verdict"]:
                    raise ValueError("PRIVATE_N04_DEFENSE_OPENING_MISMATCH")
                input_artifacts = [
                    json.loads(decrypted[ref.artifact_id.lower()])
                    for ref in feedback_events[0].artifact_ciphertext_refs
                    if json.loads(decrypted[ref.artifact_id.lower()]).get("kind") == "INPUT_OPENING"
                ]
                if len(input_artifacts) != 1:
                    raise ValueError("PRIVATE_N04_INPUT_OPENING_MISSING")
                input_opening = json.loads(
                    base64.b64decode(input_artifacts[0]["content_base64"], validate=True)
                )
                row = connection.execute(
                    "SELECT source_ref,state,known_execution FROM n04_turns WHERE turn_id=?",
                    (defense_events[0].turn_id,),
                ).fetchone()
                if (
                    row is None
                    or row["state"] != "DONE"
                    or row["known_execution"] != turn["model_execution"]
                    or not isinstance(row["source_ref"], str)
                ):
                    raise ValueError("PRIVATE_N04_DURABLE_TURN_ROW_MISMATCH")
                payload = public_corpus.records.get(row["source_ref"])
                if payload is None or payload.payload_ref != row["source_ref"]:
                    raise ValueError("PRIVATE_N04_SOURCE_REF_NOT_IN_ADMITTED_JBB")
                _validate_input_identity(
                    turn=turn,
                    opening=input_opening,
                    payload_ref=payload.payload_ref,
                    payload_text=payload.text,
                    provenance=payload.provenance.model_dump(),
                )

                model_events = [event for event in owned if event.event_type == "MODEL_RESULT"]
                if turn["model_execution"] == "NOT_EVALUATED":
                    if model_events:
                        raise ValueError("PRIVATE_N04_UNEXPECTED_MODEL_EVENT")
                    continue
                if len(model_events) != 1 or model_events[0].outcome_code != "OK":
                    raise ValueError("PRIVATE_N04_MODEL_EVENT_MISMATCH")
                model_ref = model_events[0].artifact_ciphertext_refs[0].artifact_id.lower()
                model = TargetResponse.model_validate(json.loads(decrypted[model_ref]))
                if (
                    sha256(model.attempt_id.encode("ascii")) != turn["turn_id_sha256"]
                    or model.duration_us != turn["model_latency_us"]
                    or model.input_tokens != turn["model_input_tokens"]
                    or model.output_tokens != turn["model_output_tokens"]
                    or sha256(model.text.encode("utf-8")) != turn["model_output_sha256"]
                ):
                    raise ValueError("PRIVATE_N04_MODEL_OUTPUT_MISMATCH")
        finally:
            connection.close()


def _recompute_analysis(phases: list[dict[str, Any]]) -> dict[str, Any]:
    expected = _phase_plan()
    if len(phases) != len(expected):
        raise ValueError("P013_PHASE_COUNT_MISMATCH")
    by_block_arm: dict[tuple[int, str], dict[str, Any]] = {}
    for actual, scheduled in zip(phases, expected, strict=True):
        cli = actual.get("n04_cli", {})
        turns = actual.get("turns", [])
        if (
            actual.get("block") != scheduled["block"]
            or actual.get("arm") != scheduled["arm"]
            or actual.get("result") != "MEASURED"
            or actual.get("defense_mode") != "INPUT"
            or actual.get("model_kind") != "REAL_LOCAL_QWEN_0.5B_Q4_K_M"
            or len(turns) != TURNS_PER_RUN
            or cli.get("run_label") != "REAL_PUBLIC"
            or cli.get("defense_mode") != "INPUT"
            or cli.get("real_model") is not True
            or cli.get("verifier_exit_code") != 0
            or cli.get("verifier_status") != "PASS_PUBLIC_EVIDENCE"
            or cli.get("integrity") != "VALID_WITHIN_PROFILE"
            or cli.get("turn_openings_verified") != TURNS_PER_RUN
            or cli.get("turn_count") != TURNS_PER_RUN
            or cli.get("model_dispatches") != sum(t.get("model_execution") == "EXECUTED" for t in turns)
            or cli.get("model_dispatches", 0) <= 0
            or (actual["arm"] == "SERIAL" and actual.get("serial_cli_gather_calls") != 2)
            or (actual["arm"] == "CONCURRENT" and actual.get("serial_cli_gather_calls") is not None)
        ):
            raise ValueError("P013_PHASE_OR_N04_PROJECTION_INVALID")
        keys = [_turn_key(turn) for turn in turns]
        if len(set(keys)) != TURNS_PER_RUN or {turn["lane"] for turn in turns} != {0, 1, 2}:
            raise ValueError("P013_TURN_KEYS_OR_LANES_INVALID")
        for lane in range(LANES):
            lane_turns = sorted(
                (turn for turn in turns if turn["lane"] == lane),
                key=lambda turn: turn["turn_index"],
            )
            if (
                len(lane_turns) != 2
                or [turn["turn_index"] for turn in lane_turns] != [0, 1]
                or len({turn["session_id_sha256"] for turn in lane_turns}) != 1
            ):
                raise ValueError("P013_SESSION_LANE_BINDING_INVALID")
            for turn in lane_turns:
                if (
                    turn.get("verdict") not in {"ALLOW", "BLOCK", "SANITIZE"}
                    or turn.get("defense_event_outcome") != turn.get("verdict")
                    or turn.get("pipeline_disposition")
                    != {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED_BY_DEFENSE", "SANITIZE": "SANITIZED"}.get(turn.get("verdict"))
                    or turn.get("integrity") != "VALID_WITHIN_PROFILE"
                    or type(turn.get("controller_latency_us")) is not int
                    or turn["controller_latency_us"] <= 0
                    or turn.get("model_execution") not in {"EXECUTED", "NOT_EVALUATED"}
                    or (turn["model_execution"] == "EXECUTED") != (turn.get("model_output_sha256") is not None)
                    or (turn["model_execution"] == "EXECUTED") != (type(turn.get("model_latency_us")) is int)
                    or (turn["model_execution"] == "EXECUTED" and turn["model_latency_us"] <= 0)
                    or (turn["model_execution"] == "EXECUTED") != (
                        type(turn.get("model_input_tokens")) is int
                        and type(turn.get("model_output_tokens")) is int
                    )
                ):
                    raise ValueError("P013_TURN_RESULT_INVALID")
        overlap = actual.get("model_overlap", {})
        if overlap.get("model_trace_count") != cli["model_dispatches"]:
            raise ValueError("P013_TRACE_DISPATCH_COUNT_MISMATCH")
        if actual["arm"] == "SERIAL" and (
            overlap.get("cross_lane_overlap_pairs") != 0
            or overlap.get("max_simultaneous_model_traces") != 1
        ):
            raise ValueError("P013_SERIAL_OVERLAP_INVALID")
        if actual["arm"] == "CONCURRENT" and (
            overlap.get("cross_lane_overlap_pairs", 0) < 1
            or overlap.get("max_simultaneous_model_traces") != LANES
        ):
            raise ValueError("P013_CONCURRENT_THREE_LANE_OVERLAP_NOT_OBSERVED")
        by_block_arm[(actual["block"], actual["arm"])] = actual

    paired_rows: list[dict[str, Any]] = []
    response_match_count = response_drift_count = response_pair_count = 0
    verdict_match_count = verdict_drift_count = 0
    disposition_match_count = disposition_drift_count = 0
    execution_match_count = execution_drift_count = 0
    input_token_match_count = output_token_match_count = model_token_pair_count = 0
    controller_changes: list[float] = []
    model_changes: list[float] = []
    reference_cases: set[tuple[int, str, str, int]] | None = None
    for block in range(1, len(BLOCK_ORDER) + 1):
        serial = by_block_arm[(block, "SERIAL")]
        concurrent = by_block_arm[(block, "CONCURRENT")]
        serial_turns = {_turn_key(turn): turn for turn in serial["turns"]}
        concurrent_turns = {_turn_key(turn): turn for turn in concurrent["turns"]}
        if set(serial_turns) != set(concurrent_turns):
            raise ValueError("P013_CASE_SET_MISMATCH")
        if reference_cases is None:
            reference_cases = set(serial_turns)
        elif set(serial_turns) != reference_cases:
            raise ValueError("P013_BLOCK_CASE_SET_CHANGED")
        for key in sorted(serial_turns):
            left, right = serial_turns[key], concurrent_turns[key]
            verdict_same = left["verdict"] == right["verdict"]
            verdict_match_count += int(verdict_same)
            verdict_drift_count += int(not verdict_same)
            disposition_same = left["pipeline_disposition"] == right["pipeline_disposition"]
            disposition_match_count += int(disposition_same)
            disposition_drift_count += int(not disposition_same)
            execution_same = left["model_execution"] == right["model_execution"]
            execution_match_count += int(execution_same)
            execution_drift_count += int(not execution_same)
            both_executed = left["model_execution"] == right["model_execution"] == "EXECUTED"
            input_tokens_same = output_tokens_same = None
            if both_executed:
                model_token_pair_count += 1
                input_tokens_same = left["model_input_tokens"] == right["model_input_tokens"]
                output_tokens_same = left["model_output_tokens"] == right["model_output_tokens"]
                input_token_match_count += int(input_tokens_same)
                output_token_match_count += int(output_tokens_same)
            output_same = None
            if left["model_output_sha256"] is not None and right["model_output_sha256"] is not None:
                response_pair_count += 1
                output_same = left["model_output_sha256"] == right["model_output_sha256"]
                response_match_count += int(output_same)
                response_drift_count += int(not output_same)
            controller_change = (
                (right["controller_latency_us"] - left["controller_latency_us"])
                / left["controller_latency_us"]
                * 100.0
            )
            controller_changes.append(controller_change)
            model_change = None
            if left["model_latency_us"] is not None and right["model_latency_us"] is not None:
                model_change = (
                    (right["model_latency_us"] - left["model_latency_us"])
                    / left["model_latency_us"]
                    * 100.0
                )
                model_changes.append(model_change)
            paired_rows.append(
                {
                    "block": block,
                    "lane": key[0],
                    "record_id_sha256": key[1],
                    "prompt_sha256": key[2],
                    "turn_index": key[3],
                    "serial_verdict": left["verdict"],
                    "concurrent_verdict": right["verdict"],
                    "verdict_match": verdict_same,
                    "serial_disposition": left["pipeline_disposition"],
                    "concurrent_disposition": right["pipeline_disposition"],
                    "disposition_match": disposition_same,
                    "model_execution_match": execution_same,
                    "model_output_sha256_match": output_same,
                    "input_tokens_match": input_tokens_same,
                    "output_tokens_match": output_tokens_same,
                    "controller_latency_change_percent": round(controller_change, 6),
                    "model_latency_change_percent": None if model_change is None else round(model_change, 6),
                }
            )
    if response_pair_count <= 0 or any(
        not any(row["block"] == block and row["model_output_sha256_match"] is not None for row in paired_rows)
        for block in range(1, len(BLOCK_ORDER) + 1)
    ):
        raise ValueError("P013_NO_PAIRED_REAL_MODEL_RESPONSES")
    return {
        "result": "REAL_MODEL_SERIAL_CONCURRENT_COMPARISON_OBSERVED",
        "phase_count": len(phases),
        "turn_count": sum(len(phase["turns"]) for phase in phases),
        "paired_case_count": len(paired_rows),
        "response_pair_count": response_pair_count,
        "response_match_count": response_match_count,
        "response_drift_count": response_drift_count,
        "verdict_match_count": verdict_match_count,
        "verdict_drift_count": verdict_drift_count,
        "disposition_match_count": disposition_match_count,
        "disposition_drift_count": disposition_drift_count,
        "model_execution_match_count": execution_match_count,
        "model_execution_drift_count": execution_drift_count,
        "input_token_match_count": input_token_match_count,
        "output_token_match_count": output_token_match_count,
        "model_token_pair_count": model_token_pair_count,
        "all_serial_runs_showed_no_cross_lane_model_overlap": all(
            phase["model_overlap"]["cross_lane_overlap_pairs"] == 0
            for phase in phases if phase["arm"] == "SERIAL"
        ),
        "all_concurrent_runs_showed_cross_lane_model_overlap": all(
            phase["model_overlap"]["cross_lane_overlap_pairs"] > 0
            for phase in phases if phase["arm"] == "CONCURRENT"
        ),
        "serial_run_count": sum(phase["arm"] == "SERIAL" for phase in phases),
        "concurrent_run_count": sum(phase["arm"] == "CONCURRENT" for phase in phases),
        "controller_latency_change_percent_median": round(statistics.median(controller_changes), 6),
        "controller_latency_change_percent_min": round(min(controller_changes), 6),
        "controller_latency_change_percent_max": round(max(controller_changes), 6),
        "model_latency_change_percent_median": round(statistics.median(model_changes), 6),
        "model_latency_change_percent_min": round(min(model_changes), 6),
        "model_latency_change_percent_max": round(max(model_changes), 6),
        "paired_rows": paired_rows,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "host_cpu_exclusivity_verified": False,
        "guarantee_tier_achieved": None,
    }


def verify(
    *,
    observation_path: Path,
    lock_path: Path,
    model_path: Path,
    corpus_path: Path,
    corpus_receipt_path: Path,
    corpus_keys_path: Path,
) -> dict[str, Any]:
    observation_path = observation_path.resolve()
    lock_path, model_path, corpus_path, corpus_receipt_path, corpus_keys_path = (
        lock_path.resolve(),
        model_path.resolve(),
        corpus_path.resolve(),
        corpus_receipt_path.resolve(),
        corpus_keys_path.resolve(),
    )
    if not _inside_artifacts(observation_path):
        raise ValueError("OBSERVATION_OUTSIDE_PRIVATE_ARTIFACTS")
    observation = json.loads(observation_path.read_text(encoding="utf-8"))
    if (
        observation.get("scope") != SCOPE
        or observation.get("result") != "REAL_MODEL_SERIAL_CONCURRENT_COMPARISON_OBSERVED"
        or observation.get("real_inference_performed") is not True
        or observation.get("real_public_jbb_used") is not True
        or observation.get("defense_pipeline_exercised") is not True
        or observation.get("mode") != "INPUT"
        or observation.get("model_kind") != "REAL_LOCAL_QWEN_0.5B_Q4_K_M"
        or observation.get("p011_complete") is not False
        or observation.get("p013_complete") is not False
        or observation.get("full_n07_acceptance") is not False
        or observation.get("full_arena_acceptance") is not False
        or observation.get("guarantee_tier_achieved") is not None
    ):
        raise ValueError("OBSERVATION_SCOPE_OR_STATUS_INVALID")
    if (
        not all(path.is_file() for path in (lock_path, model_path, corpus_receipt_path, corpus_keys_path))
        or not corpus_path.is_dir()
    ):
        raise FileNotFoundError("VERIFIER_INPUT_MISSING")
    if (
        digest_file(lock_path) != observation.get("lock_sha256")
        or digest_file(model_path) != observation.get("model_sha256")
        or digest_file(corpus_receipt_path) != observation.get("corpus_receipt_sha256")
    ):
        raise ValueError("ADMITTED_INPUT_HASH_MISMATCH")
    lock_sha256 = digest_file(lock_path)
    admission = load_wire(LaneAdmission, lock_path.read_bytes())
    if (
        model_path.name != admission.model_filename
        or digest_file(model_path) != admission.model_sha256
        or digest_file(model_path.parent / "LICENSE") != admission.model_license_sha256
        or digest_file(corpus_receipt_path) != admission.corpus_receipt_sha256
    ):
        raise ValueError("ADMISSION_MODEL_LICENSE_OR_CORPUS_MISMATCH")
    if runtime_source_hashes() != admission.runtime_source_sha256:
        raise ValueError("N05_RUNTIME_SOURCE_HASH_MISMATCH")
    cell_lock_path = lock_path.parent / "cell-admission.json"
    if (
        not cell_lock_path.is_file()
        or digest_file(cell_lock_path) != admission.cell_admission_sha256
    ):
        raise ValueError("N05_CELL_ADMISSION_HASH_MISMATCH")
    cell_admission = load_wire(AdmissionLock, cell_lock_path.read_bytes()).model_dump()
    lane_admission = admission.model_dump()
    if any(
        lane_admission.get(name) != value
        for name, value in cell_admission.items()
        if name not in {"schema_version", "claim_scope"}
    ):
        raise ValueError("N05_CELL_BASE_PROFILE_MISMATCH")
    public_corpus = PreparedPublicCorpus(
        corpus_path,
        corpus_receipt_path,
        corpus_keys_path,
        admission.corpus_receipt_sha256,
    )
    current_sources = source_hashes()
    if (
        set(observation.get("source_sha256", {})) != set(SOURCE_FILES)
        or observation.get("source_unchanged_during_run") is not True
        or observation.get("source_sha256") != current_sources
        or observation.get("source_sha256_after") != current_sources
    ):
        raise ValueError("CURRENT_SOURCE_BINDING_MISMATCH")
    pre = observation.get("pre_run_container_check", {})
    post = observation.get("post_run_container_check", {})
    if (
        pre.get("result") != "PASS"
        or pre.get("running_container_count") != 0
        or post.get("result") != "PASS"
        or post.get("running_container_count") != 0
        or post.get("all_container_inventory_unchanged") is not True
        or post.get("added_container_name_sha256") != []
        or post.get("removed_container_name_sha256") != []
    ):
        raise ValueError("CONTAINER_INVENTORY_CHECK_FAILED")

    phases = observation.get("phases")
    expected_phases = _phase_plan()
    if not isinstance(phases, list) or len(phases) != len(expected_phases):
        raise ValueError("PHASE_LIST_INVALID")
    output_root = observation_path.parent.resolve()
    if not _inside_artifacts(output_root):
        raise ValueError("OUTPUT_ROOT_OUTSIDE_PRIVATE_ARTIFACTS")
    for phase, scheduled in zip(phases, expected_phases, strict=True):
        phase_name = f"block-{scheduled['block']}-{scheduled['arm'].lower()}"
        private_run = (ROOT / phase.get("private_run_path", "")).resolve()
        expected_run = (output_root / phase_name).resolve()
        if private_run != expected_run or not _inside_artifacts(private_run):
            raise ValueError("PRIVATE_N04_RUN_PATH_MISMATCH")
        summary_path = private_run / "summary.json"
        bundle_path = private_run / "public-evidence.zip"
        if (
            not summary_path.is_file()
            or digest_file(summary_path) != phase.get("n04_summary_sha256")
            or not bundle_path.is_file()
            or digest_file(bundle_path) != phase.get("public_bundle_sha256")
        ):
            raise ValueError("N04_PRIVATE_ARTIFACT_HASH_MISMATCH")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        diagnostics = summary.get("verifier_result", {}).get("diagnostics", {})
        if (
            summary.get("run_label") != "REAL_PUBLIC"
            or summary.get("defense_mode") != "INPUT"
            or summary.get("real_model") is not True
            or summary.get("turns") != TURNS_PER_RUN
            or summary.get("lane_count") != LANES
            or type(summary.get("model_dispatches")) is not int
            or summary.get("model_dispatches") <= 0
            or summary.get("verifier_exit_code") != 0
            or summary.get("verifier_result", {}).get("status") != "PASS_PUBLIC_EVIDENCE"
            or diagnostics.get("integrity") != "VALID_WITHIN_PROFILE"
            or diagnostics.get("turn_openings_verified") != TURNS_PER_RUN
        ):
            raise ValueError("PRIVATE_N04_SUMMARY_ACCEPTANCE_MISMATCH")
        _validate_private_results(phase=phase, summary=summary, lock_sha256=lock_sha256)
        selected_traces = _select_private_traces(phase["turns"], summary.get("model_trace", []))
        if _overlap_summary(selected_traces) != phase.get("model_overlap"):
            raise ValueError("MODEL_OVERLAP_RECOMPUTATION_MISMATCH")
        if (
            phase.get("block") != scheduled["block"]
            or phase.get("arm") != scheduled["arm"]
            or phase.get("model_kind") != "REAL_LOCAL_QWEN_0.5B_Q4_K_M"
            or phase.get("n04_cli", {}).get("model_dispatches") != summary.get("model_dispatches")
            or phase.get("n04_cli", {}).get("defense_mode") != summary.get("defense_mode")
            or phase.get("n04_cli", {}).get("real_model") is not summary.get("real_model")
        ):
            raise ValueError("PUBLIC_N04_PROJECTION_MISMATCH")
        trust = json.loads((private_run / "trusted-context.json").read_text(encoding="utf-8"))
        _rerun_private_verifier(private_run, trust)
        _verify_private_events_and_model(
            private_run=private_run,
            phase=phase,
            trust=trust,
            public_corpus=public_corpus,
        )

    recomputed = _recompute_analysis(phases)
    if recomputed != observation.get("analysis"):
        raise ValueError("ANALYSIS_RECOMPUTATION_MISMATCH")
    return {
        "result": "PASS_SOURCE_AND_PRIVATE_N04_RECONCILIATION",
        "scope": SCOPE,
        "phase_count": recomputed["phase_count"],
        "turn_count": recomputed["turn_count"],
        "paired_case_count": recomputed["paired_case_count"],
        "response_pair_count": recomputed["response_pair_count"],
        "response_match_count": recomputed["response_match_count"],
        "response_drift_count": recomputed["response_drift_count"],
        "verdict_drift_count": recomputed["verdict_drift_count"],
        "disposition_drift_count": recomputed["disposition_drift_count"],
        "model_execution_drift_count": recomputed["model_execution_drift_count"],
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--corpus", required=True, type=Path)
    parser.add_argument("--corpus-receipt", required=True, type=Path)
    parser.add_argument("--corpus-keys", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(
            observation_path=args.observation,
            lock_path=args.lock,
            model_path=args.model,
            corpus_path=args.corpus,
            corpus_receipt_path=args.corpus_receipt,
            corpus_keys_path=args.corpus_keys,
        )
    except Exception as exc:
        failure_code = str(exc)
        if not failure_code.isascii() or not failure_code.isupper():
            failure_code = None
        print(
            json.dumps(
                {
                    "result": "FAIL_RECONCILIATION",
                    "failure_type": type(exc).__name__,
                    "failure_code": failure_code,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
