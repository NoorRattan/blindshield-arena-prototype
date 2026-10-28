"""Run a bounded real-N04 serial/concurrent comparison on admitted public JBB inputs.

The six-turn workload is repeated in three counterbalanced blocks. Each arm uses
fresh three-lane N05 cells and the actual N04 controller/INPUT defense path. A
measurement-only CLI proxy serializes each three-turn wave in the serial arm;
the concurrent arm uses the unchanged CLI schedule. This is not full P-013,
resource fairness, N07, or Arena acceptance.
"""

from __future__ import annotations

import argparse
import asyncio
from contextvars import ContextVar
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import re
import statistics
import sys
import time
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
BLOCK_ORDER = (
    (("SERIAL", "CONCURRENT"), ("CONCURRENT", "SERIAL"), ("SERIAL", "CONCURRENT"))
)
TURNS_PER_RUN = 6
LANES = 3
SCOPE = "N07B_BOUNDED_REAL_MODEL_SERIAL_CONCURRENT_INPUT_PATH_COMPARISON"
_CURRENT_TURN: ContextVar[dict[str, Any] | None] = ContextVar(
    "n07b_p013_real_serial_concurrent_turn", default=None
)

sys.path.insert(0, str(ROOT))

from arena.contracts.crypto import sha256  # noqa: E402
from arena.integration import cli as n04_cli  # noqa: E402
from arena.integration.controller import N04Controller  # noqa: E402
from arena.integration.lanes import ThreeLaneRuntime  # noqa: E402
from arena.integration.runtime import docker, ensure_local_docker, runtime_source_hashes  # noqa: E402
from tools.run_n07b_resource_fairness_verdict_matrix import (  # noqa: E402
    check_model_limits,
    measured_model_traces,
    model_overlap_summary,
    running_containers,
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


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def source_hashes() -> dict[str, str]:
    return {name: digest_file(ROOT / name) for name in SOURCE_FILES}


def all_container_names() -> set[str]:
    return {
        item
        for item in docker("ps", "-a", "--format", "{{.Names}}")
        .decode()
        .splitlines()
        if item
    }


def phase_plan() -> list[dict[str, Any]]:
    return [
        {"block": block, "arm": arm}
        for block, order in enumerate(BLOCK_ORDER, start=1)
        for arm in order
    ]


class SerialCliAsyncioProxy:
    """Replace only the CLI module's gather with ordered execution of one wave."""

    def __init__(self, real_asyncio: Any):
        self._real_asyncio = real_asyncio
        self.gather_calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_asyncio, name)

    async def gather(self, *awaitables: Any, **kwargs: Any) -> list[Any]:
        if len(awaitables) != LANES or set(kwargs) - {"return_exceptions"}:
            raise RuntimeError("UNEXPECTED_SERIAL_CLI_GATHER_SHAPE")
        return_exceptions = kwargs.get("return_exceptions", False)
        if type(return_exceptions) is not bool:
            raise RuntimeError("SERIAL_CLI_GATHER_EXCEPTION_POLICY_INVALID")
        self.gather_calls += 1
        results: list[Any] = []
        for index, awaitable in enumerate(awaitables):
            try:
                results.append(await awaitable)
            except BaseException as exc:
                if not return_exceptions:
                    for pending in awaitables[index + 1 :]:
                        close = getattr(pending, "close", None)
                        if close is not None:
                            close()
                    raise
                results.append(exc)
        return results


def _turn_key(turn: dict[str, Any]) -> tuple[int, str, str, int]:
    return (
        turn["lane"],
        turn["record_id_sha256"],
        turn["prompt_sha256"],
        turn["turn_index"],
    )


def analyze_phases(phases: list[dict[str, Any]]) -> dict[str, Any]:
    expected = phase_plan()
    if len(phases) != len(expected):
        raise ValueError("P013_PHASE_COUNT_MISMATCH")
    by_block_arm: dict[tuple[int, str], dict[str, Any]] = {}
    for actual, scheduled in zip(phases, expected, strict=True):
        if (
            actual.get("block") != scheduled["block"]
            or actual.get("arm") != scheduled["arm"]
            or actual.get("result") != "MEASURED"
            or actual.get("defense_mode") != "INPUT"
            or len(actual.get("turns", [])) != TURNS_PER_RUN
            or actual.get("n04_cli", {}).get("run_label") != "REAL_PUBLIC"
            or actual.get("n04_cli", {}).get("defense_mode") != "INPUT"
            or actual.get("n04_cli", {}).get("real_model") is not True
            or actual.get("n04_cli", {}).get("verifier_exit_code") != 0
            or actual.get("n04_cli", {}).get("verifier_status") != "PASS_PUBLIC_EVIDENCE"
            or actual.get("n04_cli", {}).get("integrity") != "VALID_WITHIN_PROFILE"
            or actual.get("n04_cli", {}).get("turn_openings_verified") != TURNS_PER_RUN
            or actual.get("n04_cli", {}).get("turn_count") != TURNS_PER_RUN
            or actual.get("n04_cli", {}).get("model_dispatches")
            != sum(turn.get("model_execution") == "EXECUTED" for turn in actual.get("turns", []))
            or actual.get("n04_cli", {}).get("model_dispatches", 0) <= 0
            or (actual["arm"] == "SERIAL" and actual.get("serial_cli_gather_calls") != 2)
            or (actual["arm"] == "CONCURRENT" and actual.get("serial_cli_gather_calls") is not None)
        ):
            raise ValueError("P013_PHASE_INVALID_OR_N04_VERIFICATION_FAILED")
        keys = [_turn_key(turn) for turn in actual["turns"]]
        if len(set(keys)) != TURNS_PER_RUN or {turn["lane"] for turn in actual["turns"]} != {0, 1, 2}:
            raise ValueError("P013_TURN_KEYS_OR_LANES_INVALID")
        for lane in range(LANES):
            lane_turns = sorted((turn for turn in actual["turns"] if turn["lane"] == lane), key=lambda item: item["turn_index"])
            if (
                len(lane_turns) != 2
                or [turn["turn_index"] for turn in lane_turns] != [0, 1]
                or len({turn["session_id_sha256"] for turn in lane_turns}) != 1
            ):
                raise ValueError("P013_LANE_SESSION_BINDING_INVALID")
            for turn in lane_turns:
                if (
                    turn["verdict"] not in {"ALLOW", "BLOCK", "SANITIZE"}
                    or type(turn["controller_latency_us"]) is not int
                    or turn["controller_latency_us"] <= 0
                    or turn["model_execution"] not in {"EXECUTED", "NOT_EVALUATED"}
                    or turn["defense_event_outcome"] != turn["verdict"]
                    or turn["pipeline_disposition"]
                    != {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED_BY_DEFENSE", "SANITIZE": "SANITIZED"}.get(turn["verdict"])
                    or turn["integrity"] != "VALID_WITHIN_PROFILE"
                    or (turn["model_execution"] == "EXECUTED") != (turn["model_output_sha256"] is not None)
                    or (turn["model_execution"] == "EXECUTED") != (type(turn["model_latency_us"]) is int)
                    or (turn["model_execution"] == "EXECUTED" and turn["model_latency_us"] <= 0)
                    or (turn["model_execution"] == "EXECUTED")
                    != (type(turn["model_input_tokens"]) is int and type(turn["model_output_tokens"]) is int)
                    or (turn["model_execution"] == "EXECUTED")
                    != (isinstance(turn["model_output_sha256"], str)
                        and re.fullmatch(r"[0-9a-f]{64}", turn["model_output_sha256"]) is not None)
                ):
                    raise ValueError("P013_DEFENSE_OR_MODEL_PAIR_INVALID")
        overlap = actual.get("model_overlap", {})
        if overlap.get("model_trace_count") != actual["n04_cli"]["model_dispatches"]:
            raise ValueError("P013_MODEL_TRACE_DISPATCH_COUNT_MISMATCH")
        if actual["arm"] == "SERIAL" and overlap.get("cross_lane_overlap_pairs") != 0:
            raise ValueError("P013_SERIAL_ARM_OVERLAP_OBSERVED")
        expected_max_active = 1 if actual["arm"] == "SERIAL" and actual["n04_cli"]["model_dispatches"] else 0
        if actual["arm"] == "SERIAL" and overlap.get("max_simultaneous_model_traces") != expected_max_active:
            raise ValueError("P013_SERIAL_MAX_OVERLAP_INVALID")
        if actual["arm"] == "CONCURRENT" and (
            overlap.get("cross_lane_overlap_pairs", 0) < 1
            or overlap.get("max_simultaneous_model_traces") != LANES
        ):
            raise ValueError("P013_CONCURRENT_THREE_LANE_OVERLAP_NOT_OBSERVED")
        if overlap.get("max_simultaneous_model_traces") != (
            LANES if actual["arm"] == "CONCURRENT" else 1
        ):
            raise ValueError("P013_ARM_MAX_OVERLAP_INVALID")
        by_block_arm[(actual["block"], actual["arm"])] = actual

    paired_rows: list[dict[str, Any]] = []
    response_match_count = 0
    response_drift_count = 0
    response_pair_count = 0
    verdict_match_count = 0
    verdict_drift_count = 0
    disposition_match_count = 0
    disposition_drift_count = 0
    execution_match_count = 0
    execution_drift_count = 0
    input_token_match_count = 0
    output_token_match_count = 0
    model_token_pair_count = 0
    latency_changes: list[float] = []
    model_latency_changes: list[float] = []
    reference_case_set: set[tuple[int, str, str, int]] | None = None
    for block in range(1, len(BLOCK_ORDER) + 1):
        serial = by_block_arm[(block, "SERIAL")]
        concurrent = by_block_arm[(block, "CONCURRENT")]
        serial_turns = {_turn_key(turn): turn for turn in serial["turns"]}
        concurrent_turns = {_turn_key(turn): turn for turn in concurrent["turns"]}
        if set(serial_turns) != set(concurrent_turns):
            raise ValueError("P013_SERIAL_CONCURRENT_CASE_SET_MISMATCH")
        if reference_case_set is None:
            reference_case_set = set(serial_turns)
        elif set(serial_turns) != reference_case_set:
            raise ValueError("P013_BLOCK_CASE_SET_CHANGED")
        for key in sorted(serial_turns):
            left, right = serial_turns[key], concurrent_turns[key]
            verdict_same = left["verdict"] == right["verdict"]
            if verdict_same:
                verdict_match_count += 1
            else:
                verdict_drift_count += 1
            disposition_same = left["pipeline_disposition"] == right["pipeline_disposition"]
            disposition_match_count += int(disposition_same)
            disposition_drift_count += int(not disposition_same)
            execution_same = left["model_execution"] == right["model_execution"]
            execution_match_count += int(execution_same)
            execution_drift_count += int(not execution_same)
            both_executed = (
                left["model_execution"] == "EXECUTED"
                and right["model_execution"] == "EXECUTED"
            )
            input_tokens_same: bool | None = None
            output_tokens_same: bool | None = None
            if both_executed:
                model_token_pair_count += 1
                input_tokens_same = left["model_input_tokens"] == right["model_input_tokens"]
                output_tokens_same = left["model_output_tokens"] == right["model_output_tokens"]
                input_token_match_count += int(input_tokens_same)
                output_token_match_count += int(output_tokens_same)
            output_same: bool | None = None
            if left["model_output_sha256"] is not None and right["model_output_sha256"] is not None:
                response_pair_count += 1
                output_same = left["model_output_sha256"] == right["model_output_sha256"]
                if output_same:
                    response_match_count += 1
                else:
                    response_drift_count += 1
            latency_changes.append(
                (right["controller_latency_us"] - left["controller_latency_us"])
                / left["controller_latency_us"]
                * 100.0
            )
            model_latency_change = None
            if left["model_latency_us"] is not None and right["model_latency_us"] is not None:
                model_latency_change = (
                    (right["model_latency_us"] - left["model_latency_us"])
                    / left["model_latency_us"]
                    * 100.0
                )
                model_latency_changes.append(model_latency_change)
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
                    "disposition_match": left["pipeline_disposition"] == right["pipeline_disposition"],
                    "model_execution_match": left["model_execution"] == right["model_execution"],
                    "model_output_sha256_match": output_same,
                    "input_tokens_match": input_tokens_same,
                    "output_tokens_match": output_tokens_same,
                    "controller_latency_change_percent": round(latency_changes[-1], 6),
                    "model_latency_change_percent": None if model_latency_change is None else round(model_latency_change, 6),
                }
            )

    if response_pair_count <= 0 or any(
        not any(
            row["block"] == block and row["model_output_sha256_match"] is not None
            for row in paired_rows
        )
        for block in range(1, len(BLOCK_ORDER) + 1)
    ):
        raise ValueError("P013_NO_PAIRED_REAL_MODEL_RESPONSES")

    all_serial_no_overlap = all(
        phase["model_overlap"]["cross_lane_overlap_pairs"] == 0
        for phase in phases
        if phase["arm"] == "SERIAL"
    )
    all_concurrent_overlap = all(
        phase["model_overlap"]["cross_lane_overlap_pairs"] > 0
        for phase in phases
        if phase["arm"] == "CONCURRENT"
    )
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
        "all_serial_runs_showed_no_cross_lane_model_overlap": all_serial_no_overlap,
        "all_concurrent_runs_showed_cross_lane_model_overlap": all_concurrent_overlap,
        "serial_run_count": sum(phase["arm"] == "SERIAL" for phase in phases),
        "concurrent_run_count": sum(phase["arm"] == "CONCURRENT" for phase in phases),
        "controller_latency_change_percent_median": round(statistics.median(latency_changes), 6),
        "controller_latency_change_percent_min": round(min(latency_changes), 6),
        "controller_latency_change_percent_max": round(max(latency_changes), 6),
        "model_latency_change_percent_median": round(statistics.median(model_latency_changes), 6) if model_latency_changes else None,
        "model_latency_change_percent_min": round(min(model_latency_changes), 6) if model_latency_changes else None,
        "model_latency_change_percent_max": round(max(model_latency_changes), 6) if model_latency_changes else None,
        "paired_rows": paired_rows,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "host_cpu_exclusivity_verified": False,
        "guarantee_tier_achieved": None,
    }


class RunCapture:
    def __init__(self, scheduled: dict[str, Any], output: Path):
        self.scheduled = scheduled
        self.output = output
        self.runtime: ThreeLaneRuntime | None = None
        self.turns: list[dict[str, Any]] = []
        self.cli_summary: dict[str, Any] | None = None
        self.serial_proxy: SerialCliAsyncioProxy | None = None

    def json_phase(self) -> dict[str, Any]:
        if self.cli_summary is None or self.runtime is None or self.runtime.model is None:
            raise RuntimeError("P013_PHASE_NOT_CAPTURED")
        traces = measured_model_traces(self.turns, self.cli_summary.get("model_trace", []))
        overlap = model_overlap_summary(traces)
        return {
            **self.scheduled,
            "result": "MEASURED",
            "defense_mode": "INPUT",
            "runtime_scope": "N05_THREE_PROCESS_BASELINE",
            "turns": sorted(self.turns, key=lambda item: (item["lane"], item["turn_index"])),
            "model_overlap": overlap,
            "model_overlap_scope": "N04_CONTROLLER_TURNS_ONLY; N05_STARTUP_TRACES_EXCLUDED_BY_EXACT_TURN_ID",
            "serial_cli_gather_calls": self.serial_proxy.gather_calls if self.serial_proxy else None,
            "private_run_path": self.output.relative_to(ROOT).as_posix(),
            "n04_summary_sha256": digest_file(self.output / "summary.json"),
            "public_bundle_sha256": digest_file(self.output / "public-evidence.zip"),
            "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M",
            "n04_cli": {
                "run_label": self.cli_summary["run_label"],
                "defense_mode": self.cli_summary["defense_mode"],
                "real_model": self.cli_summary["real_model"],
                "turn_count": self.cli_summary["turns"],
                "model_dispatches": self.cli_summary["model_dispatches"],
                "verifier_exit_code": self.cli_summary["verifier_exit_code"],
                "verifier_status": self.cli_summary["verifier_result"]["status"],
                "integrity": self.cli_summary["verifier_result"]["diagnostics"]["integrity"],
                "turn_openings_verified": self.cli_summary["verifier_result"]["diagnostics"]["turn_openings_verified"],
            },
        }


class DriftRunner:
    def __init__(self, *, lock: Path, model: Path, corpus: Path, corpus_receipt: Path, corpus_keys: Path):
        self.lock, self.model, self.corpus = lock, model, corpus
        self.corpus_receipt, self.corpus_keys = corpus_receipt, corpus_keys
        self.phase: RunCapture | None = None
        self.originals: dict[str, Any] = {}
        self.container_names_before: set[str] = set()

    def install(self) -> None:
        self.originals = {
            "start": ThreeLaneRuntime.start,
            "turn": N04Controller.turn,
            "defend": N04Controller._defend,
        }
        original_start = self.originals["start"]
        original_turn = self.originals["turn"]
        original_defend = self.originals["defend"]

        def start(runtime: ThreeLaneRuntime):
            inspection = original_start(runtime)
            phase = self.phase
            if phase is None:
                raise RuntimeError("P013_PHASE_NOT_SET")
            phase.runtime = runtime
            check_model_limits(runtime, inspection)
            original_infer = runtime.model.infer

            async def tracked_infer(request):
                response = await original_infer(request)
                sample = _CURRENT_TURN.get()
                if sample is not None:
                    if sample.get("model") is not None:
                        raise RuntimeError("P013_MULTIPLE_MODEL_RESPONSES_FOR_TURN")
                    sample["model"] = {
                        "attempt_id_sha256": sha256(request.attempt_id.encode("ascii")),
                        "duration_us": response.duration_us,
                        "input_tokens": response.input_tokens,
                        "output_tokens": response.output_tokens,
                        "output_sha256": sha256(response.text.encode("utf-8")),
                    }
                return response

            runtime.model.infer = tracked_infer
            return inspection

        async def defend(controller: N04Controller, request):
            decision = await original_defend(controller, request)
            sample = _CURRENT_TURN.get()
            if sample is not None:
                if sample.get("verdict") is not None:
                    raise RuntimeError("P013_MULTIPLE_DEFENSE_DECISIONS_FOR_TURN")
                sample["verdict"] = decision.verdict
            return decision

        async def turn(controller: N04Controller, principal, session_id, request, key, payload):
            sample: dict[str, Any] = {
                "record_id_sha256": sha256(payload.provenance.record_id.encode("utf-8")),
                "prompt_sha256": sha256(payload.text.encode("utf-8")),
                "payload_reference_sha256": sha256(payload.payload_ref.encode("ascii")),
                "turn_index": request.turn_index,
                "model": None,
                "verdict": None,
            }
            token = _CURRENT_TURN.set(sample)
            try:
                started = time.perf_counter_ns()
                result = await original_turn(controller, principal, session_id, request, key, payload)
                controller_latency_us = max(1, (time.perf_counter_ns() - started) // 1000)
                if sample["verdict"] is None:
                    # The CLI's exact idempotent replay returns before defense/model dispatch.
                    return result
                events = [
                    event for event in controller.recorder.get_events(controller.ctx)
                    if event.turn_id == result.turn_id and event.event_type == "DEFENSE_RESULT"
                ]
                if len(events) != 1 or events[0].outcome_code != sample["verdict"]:
                    raise RuntimeError("P013_DEFENSE_EVENT_VERDICT_MISMATCH")
                lane_name = controller.runtime.model.get_assigned_lane(session_id)
                match = re.fullmatch(r"lane-([0-2])", lane_name or "")
                if match is None:
                    raise RuntimeError("P013_LANE_BINDING_MISSING")
                lane = int(match.group(1))
                disposition = result.result.pipeline_disposition
                expected = {"ALLOW": "ALLOWED", "BLOCK": "BLOCKED_BY_DEFENSE", "SANITIZE": "SANITIZED"}[sample["verdict"]]
                if disposition != expected:
                    raise RuntimeError("P013_DEFENSE_DISPOSITION_MISMATCH")
                model = sample["model"]
                if (result.result.model_execution == "EXECUTED") != (model is not None):
                    raise RuntimeError("P013_MODEL_EXECUTION_TRACE_MISMATCH")
                phase = self.phase
                if phase is None:
                    raise RuntimeError("P013_PHASE_NOT_SET")
                phase.turns.append(
                    {
                        "lane": lane,
                        "session_id_sha256": sha256(session_id.encode("ascii")),
                        "record_id_sha256": sample["record_id_sha256"],
                        "prompt_sha256": sample["prompt_sha256"],
                        "payload_reference_sha256": sample["payload_reference_sha256"],
                        "turn_index": sample["turn_index"],
                        "turn_id_sha256": sha256(result.turn_id.encode("ascii")),
                        "verdict": sample["verdict"],
                        "defense_event_outcome": events[0].outcome_code,
                        "pipeline_disposition": disposition,
                        "integrity": result.result.integrity,
                        "model_execution": result.result.model_execution,
                        "controller_latency_us": controller_latency_us,
                        "model_latency_us": model["duration_us"] if model else None,
                        "model_input_tokens": model["input_tokens"] if model else None,
                        "model_output_tokens": model["output_tokens"] if model else None,
                        "model_output_sha256": model["output_sha256"] if model else None,
                    }
                )
                if len(phase.turns) > TURNS_PER_RUN:
                    raise RuntimeError("P013_TURN_COUNT_EXCEEDED")
                return result
            finally:
                _CURRENT_TURN.reset(token)

        ThreeLaneRuntime.start = start
        N04Controller.turn = turn
        N04Controller._defend = defend

    def restore(self) -> None:
        if not self.originals:
            return
        ThreeLaneRuntime.start = self.originals["start"]
        N04Controller.turn = self.originals["turn"]
        N04Controller._defend = self.originals["defend"]
        self.originals.clear()

    async def run_phase(self, scheduled: dict[str, Any], output: Path) -> dict[str, Any]:
        self.phase = RunCapture(scheduled, output)
        args = SimpleNamespace(
            lock=self.lock,
            model=self.model,
            corpus=self.corpus,
            corpus_receipt=self.corpus_receipt,
            corpus_keys=self.corpus_keys,
            output=output,
            mode="INPUT",
            traffic="real",
            lanes=LANES,
            n06_policy=None,
            n06_policy_public_key=None,
            n06_policy_key_id=None,
            n06_local_mtls=False,
            n06_sealed_profile=False,
            n06_workload="six",
        )
        old_cli_asyncio = n04_cli.asyncio
        if scheduled["arm"] == "SERIAL":
            self.phase.serial_proxy = SerialCliAsyncioProxy(asyncio)
            n04_cli.asyncio = self.phase.serial_proxy
        stdout = io.StringIO()
        try:
            with redirect_stdout(stdout):
                return_code = await asyncio.wait_for(n04_cli.run(args), timeout=900)
        finally:
            n04_cli.asyncio = old_cli_asyncio
            output.mkdir(parents=True, exist_ok=True)
            (output / "n04-cli-stdout.log").write_text(stdout.getvalue(), encoding="utf-8")
        if return_code != 0:
            raise RuntimeError("N04_CLI_RUN_FAILED")
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        if (
            summary.get("run_label") != "REAL_PUBLIC"
            or summary.get("defense_mode") != "INPUT"
            or summary.get("real_model") is not True
            or summary.get("turns") != TURNS_PER_RUN
            or summary.get("verifier_exit_code") != 0
            or summary.get("verifier_result", {}).get("status") != "PASS_PUBLIC_EVIDENCE"
            or summary.get("verifier_result", {}).get("diagnostics", {}).get("integrity") != "VALID_WITHIN_PROFILE"
            or summary.get("verifier_result", {}).get("diagnostics", {}).get("turn_openings_verified") != TURNS_PER_RUN
            or summary.get("lane_count") != LANES
        ):
            raise RuntimeError("N04_CLI_ACCEPTANCE_MISMATCH")
        self.phase.cli_summary = summary
        if len(self.phase.turns) != TURNS_PER_RUN:
            raise RuntimeError("N04_TURN_OBSERVATIONS_INCOMPLETE")
        executed_turns = sum(turn["model_execution"] == "EXECUTED" for turn in self.phase.turns)
        if executed_turns != summary["model_dispatches"]:
            raise RuntimeError("N04_DISPATCH_COUNT_MISMATCH")
        if scheduled["arm"] == "SERIAL" and self.phase.serial_proxy.gather_calls != 2:
            raise RuntimeError("SERIAL_CLI_WAVE_COUNT_MISMATCH")
        phase_value = self.phase.json_phase()
        if phase_value["model_overlap"].get("model_trace_count", 0) != executed_turns:
            raise RuntimeError("P013_MEASURED_MODEL_TRACE_COUNT_MISMATCH")
        if executed_turns <= 0:
            raise RuntimeError("P013_NO_REAL_MODEL_EXECUTION_IN_PHASE")
        ensure_local_docker()
        if running_containers():
            raise RuntimeError("OWNED_PHASE_LEFT_RUNNING_CONTAINERS")
        if all_container_names() != self.container_names_before:
            raise RuntimeError("OWNED_PHASE_CONTAINER_INVENTORY_CHANGED")
        return phase_value


async def await_phase(runner: DriftRunner, scheduled: dict[str, Any], output: Path) -> dict[str, Any]:
    return await runner.run_phase(scheduled, output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "model", "corpus", "corpus-receipt", "corpus-keys", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    lock, model, corpus = args.lock.resolve(), args.model.resolve(), args.corpus.resolve()
    receipt, keys, output = args.corpus_receipt.resolve(), args.corpus_keys.resolve(), args.output.resolve()
    if not all(path.is_file() for path in (lock, model, receipt, keys)) or not corpus.is_dir():
        raise FileNotFoundError("ADMITTED_LOCAL_MODEL_OR_PUBLIC_CORPUS_INPUT_MISSING")
    if not output.is_relative_to(ARTIFACTS.resolve()) or output.exists():
        raise ValueError("NEW_PRIVATE_OUTPUT_DIRECTORY_REQUIRED_UNDER_BACKEND_ARTIFACTS")
    before_sources = source_hashes()
    output.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "schema_version": "arena-n07b-p013-real-serial-concurrent.v1",
        "scope": SCOPE,
        "result": "INCONCLUSIVE",
        "real_inference_performed": False,
        "real_public_jbb_used": False,
        "defense_pipeline_exercised": False,
        "mode": "INPUT",
        "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M",
        "lock_sha256": digest_file(lock),
        "model_sha256": digest_file(model),
        "corpus_receipt_sha256": digest_file(receipt),
        "source_sha256": before_sources,
        "host_cpu_exclusivity_verified": False,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }
    phases: list[dict[str, Any]] = []
    runner = DriftRunner(lock=lock, model=model, corpus=corpus, corpus_receipt=receipt, corpus_keys=keys)
    try:
        from arena.contracts.jsonwire import load_wire
        from arena.integration.lanes import LaneAdmission

        admission = load_wire(LaneAdmission, lock.read_bytes())
        if runtime_source_hashes() != admission.runtime_source_sha256:
            raise RuntimeError("N05_RUNTIME_SOURCE_HASH_MISMATCH")
        ensure_local_docker()
        runner.container_names_before = all_container_names()
        if running_containers():
            raise RuntimeError("PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED")
        result["pre_run_container_check"] = {
            "result": "PASS",
            "running_container_count": 0,
            "all_container_name_sha256": sorted(
                sha256(name.encode("utf-8")) for name in runner.container_names_before
            ),
        }
        runner.install()
        for scheduled in phase_plan():
            phase_output = output / f"block-{scheduled['block']}-{scheduled['arm'].lower()}"
            try:
                phase = asyncio.run(await_phase(runner, scheduled, phase_output))
            except BaseException:
                phases.append(
                    {
                        **scheduled,
                        "result": "INCOMPLETE_RETAINED",
                        "turns_observed_before_failure": len(runner.phase.turns) if runner.phase else 0,
                        "private_run_path": phase_output.relative_to(ROOT).as_posix(),
                    }
                )
                raise
            phases.append(phase)
        analysis = analyze_phases(phases)
        result.update(
            {
                "result": analysis["result"],
                "real_inference_performed": True,
                "real_public_jbb_used": True,
                "defense_pipeline_exercised": True,
                "phase_plan": phase_plan(),
                "phases": phases,
                "analysis": analysis,
                "runtime_downloads": False,
                "p011_complete": False,
                "p013_complete": False,
                "full_n07_acceptance": False,
                "full_arena_acceptance": False,
            }
        )
        return_code = 0
    except BaseException as exc:
        result["result"] = "INCONCLUSIVE"
        message = str(exc)
        result["failure_code"] = "PROBE_EXCEPTION_" + type(exc).__name__
        if re.fullmatch(r"[A-Z0-9_]+", message):
            result["failure_code"] += ":" + message
        result["partial_phases"] = phases
        return_code = 1
    finally:
        runner.restore()
    try:
        after_sources = source_hashes()
        result["source_sha256_after"] = after_sources
        result["source_unchanged_during_run"] = before_sources == after_sources
        if before_sources != after_sources:
            result["result"] = "INCONCLUSIVE"
            result["failure_code"] = "SOURCE_CHANGED_DURING_RUN"
            return_code = 1
    except BaseException as exc:
        result["source_unchanged_during_run"] = False
        result["source_hash_check_failure"] = type(exc).__name__
        result["result"] = "INCONCLUSIVE"
        result["failure_code"] = "SOURCE_HASH_FINALIZATION_FAILED"
        return_code = 1
    try:
        ensure_local_docker()
        remaining = running_containers()
        final_inventory = all_container_names()
        inventory_unchanged = final_inventory == runner.container_names_before
        result["post_run_container_check"] = {
            "result": "PASS" if not remaining and inventory_unchanged else "CONTAINER_INVENTORY_CHANGED",
            "running_container_count": len(remaining),
            "running_container_name_sha256": sorted(sha256(name.encode("utf-8")) for name in remaining),
            "all_container_inventory_unchanged": inventory_unchanged,
            "added_container_name_sha256": sorted(
                sha256(name.encode("utf-8")) for name in final_inventory - runner.container_names_before
            ),
            "removed_container_name_sha256": sorted(
                sha256(name.encode("utf-8")) for name in runner.container_names_before - final_inventory
            ),
        }
        if remaining or not inventory_unchanged:
            result["result"] = "INCONCLUSIVE"
            result["failure_code"] = "CONTAINER_INVENTORY_CHANGED_AFTER_OWNED_CLEANUP"
            return_code = 1
    except BaseException as exc:
        result["post_run_container_check"] = {
            "result": "UNVERIFIED",
            "failure_type": type(exc).__name__,
        }
        result["result"] = "INCONCLUSIVE"
        result["failure_code"] = "POST_RUN_CONTAINER_CLEANUP_UNVERIFIED"
        return_code = 1
    (output / "observation.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary = result.get("analysis", {})
    print(
        json.dumps(
            {
                "result": result["result"],
                "scope": SCOPE,
                "phase_count": len(result.get("phases", result.get("partial_phases", []))),
                "turn_count": summary.get("turn_count"),
                "paired_case_count": summary.get("paired_case_count"),
                "response_pair_count": summary.get("response_pair_count"),
                "response_drift_count": summary.get("response_drift_count"),
                "verdict_drift_count": summary.get("verdict_drift_count"),
                "p011_complete": False,
                "p013_complete": False,
                "full_n07_acceptance": False,
                "host_cpu_exclusivity_verified": False,
                "guarantee_tier_achieved": None,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
