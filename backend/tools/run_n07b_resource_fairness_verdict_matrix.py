"""Measure repeated CPU interference through the actual N04/N05 turn path.

The probe runs three counterbalanced blocks. Each phase creates a fresh real
three-lane N05 run over the same admitted public JBB records, captures the
durable DEFENSE_RESULT outcome and the matching N04Controller.turn latency,
and records actual model duration where the defense permits dispatch. A capped
no-network CPU burner shares one model lane's cpuset in the loaded arms.

This is a bounded CPU/verdict/latency observation. It does not apply RAM, PID
or I/O contention and cannot complete P-011, P-013, N07 or Arena acceptance.
"""

from __future__ import annotations

import argparse
import asyncio
from contextvars import ContextVar
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import time
from types import SimpleNamespace
from typing import Any
from uuid import uuid4
from contextlib import redirect_stdout


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
SCOPE = "N07B_REPEATED_CPU_LOAD_PAIRED_DEFENSE_VERDICT_LATENCY_OBSERVATION"
BLOCKS = 3
TURNS_PER_PHASE = 6
PHASE_TIMEOUT_SECONDS = 600
MINIMUM_STRESSOR_CPU_CORES = 0.50

sys.path.insert(0, str(ROOT))

from arena.contracts.crypto import sha256
from arena.integration.controller import N04Controller
from arena.integration.lanes import ThreeLaneRuntime, cpu_set
from arena.integration.runtime import docker, ensure_local_docker
from arena.integration.cli import run as run_n04_cli
from tools.run_n07b_resource_fairness_probe import (
    check_model_limits,
    counter_delta,
    cgroup_snapshot,
    preflight_burner,
    remove_owned_container,
    running_containers,
    start_burner,
    validate_effective_cgroups,
)


_CURRENT_TURN: ContextVar[dict[str, Any] | None] = ContextVar(
    "n07b_resource_fairness_current_turn", default=None
)


def digest_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def phase_plan() -> list[dict[str, Any]]:
    """Return fixed, counterbalanced baseline and single-lane CPU arms."""
    orders = ((0, 1, 2), (1, 2, 0), (2, 0, 1))
    phases: list[dict[str, Any]] = []
    for block, order in enumerate(orders, start=1):
        phases.append(
            {
                "phase": f"block-{block}-baseline-pre",
                "block": block,
                "condition": "BASELINE",
                "stress_lane": None,
            }
        )
        for lane in order:
            phases.append(
                {
                    "phase": f"block-{block}-cpu-load-lane-{lane}",
                    "block": block,
                    "condition": "CPU_LOAD",
                    "stress_lane": lane,
                }
            )
        phases.append(
            {
                "phase": f"block-{block}-baseline-post",
                "block": block,
                "condition": "BASELINE",
                "stress_lane": None,
            }
        )
    return phases


def model_overlap_summary(traces: list[dict[str, Any]]) -> dict[str, int | bool]:
    valid = [
        item
        for item in traces
        if type(item.get("lane")) is int
        and type(item.get("begin_ns")) is int
        and type(item.get("end_ns")) is int
        and item["end_ns"] > item["begin_ns"]
    ]
    overlap_pairs = 0
    max_active = 0
    for item in valid:
        active = sum(
            other["begin_ns"] < item["end_ns"]
            and item["begin_ns"] < other["end_ns"]
            for other in valid
        )
        max_active = max(max_active, active)
    for index, left in enumerate(valid):
        for right in valid[index + 1 :]:
            if left["lane"] != right["lane"] and max(
                left["begin_ns"], right["begin_ns"]
            ) < min(left["end_ns"], right["end_ns"]):
                overlap_pairs += 1
    return {
        "model_trace_count": len(valid),
        "cross_lane_overlap_pairs": overlap_pairs,
        "max_simultaneous_model_traces": max_active,
        "overlap_observed": overlap_pairs > 0,
    }


def _turn_key(turn: dict[str, Any]) -> tuple[int, str, str]:
    return (
        turn["lane"],
        turn["record_id_sha256"],
        turn["prompt_sha256"],
    )


def measured_model_traces(
    turns: list[dict[str, Any]], traces: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Select only traces bound to captured N04 turns; exclude N05 startup probes."""
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
            digest = sha256(turn_id.encode("ascii"))
        except UnicodeEncodeError:
            continue
        if digest not in expected:
            continue
        if digest in selected:
            raise ValueError("RESOURCE_MATRIX_DUPLICATE_MODEL_TRACE")
        if trace.get("lane") != expected[digest]["lane"]:
            raise ValueError("RESOURCE_MATRIX_MODEL_TRACE_LANE_MISMATCH")
        selected[digest] = trace
    if set(selected) != set(expected):
        raise ValueError("RESOURCE_MATRIX_MODEL_TRACE_SET_MISMATCH")
    return list(selected.values())


def analyze_phases(phases: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate matched cases and summarize verdict stability and latency effects."""
    expected = phase_plan()
    if len(phases) != len(expected):
        raise ValueError("RESOURCE_MATRIX_PHASE_COUNT_MISMATCH")
    for actual, scheduled in zip(phases, expected, strict=True):
        if (
            actual.get("phase") != scheduled["phase"]
            or actual.get("block") != scheduled["block"]
            or actual.get("condition") != scheduled["condition"]
            or actual.get("stress_lane") != scheduled["stress_lane"]
            or actual.get("result") != "MEASURED"
            or len(actual.get("turns", [])) != TURNS_PER_PHASE
        ):
            raise ValueError("RESOURCE_MATRIX_PHASE_INVALID")
        for turn in actual["turns"]:
            expected_disposition = {
                "ALLOW": "ALLOWED",
                "BLOCK": "BLOCKED_BY_DEFENSE",
                "SANITIZE": "SANITIZED",
            }.get(turn.get("verdict"))
            if (
                turn.get("defense_event_outcome") != turn.get("verdict")
                or turn.get("pipeline_disposition") != expected_disposition
                or type(turn.get("controller_latency_us")) is not int
                or turn["controller_latency_us"] <= 0
                or (turn.get("model_execution") == "EXECUTED")
                != (type(turn.get("model_latency_us")) is int)
            ):
                raise ValueError("RESOURCE_MATRIX_TURN_PAIR_INVALID")
    record_sets = []
    for phase in phases:
        keys = [_turn_key(turn) for turn in phase["turns"]]
        if len(set(keys)) != len(keys):
            raise ValueError("RESOURCE_MATRIX_DUPLICATE_CASE_KEY")
        record_sets.append(set(keys))
    if any(keys != record_sets[0] for keys in record_sets[1:]):
        raise ValueError("RESOURCE_MATRIX_CASE_SET_CHANGED")
    if any(
        len({turn["verdict"] for turn in phase["turns"]}) < 1
        or any(turn["verdict"] not in {"ALLOW", "BLOCK", "SANITIZE"} for turn in phase["turns"])
        for phase in phases
    ):
        raise ValueError("RESOURCE_MATRIX_DEFENSE_VERDICT_INVALID")

    verdict_history: dict[tuple[int, str, str], set[str]] = {}
    output_history: dict[tuple[int, str, str], set[str]] = {}
    for phase in phases:
        for turn in phase["turns"]:
            key = _turn_key(turn)
            verdict_history.setdefault(key, set()).add(turn["verdict"])
            if turn.get("model_output_sha256"):
                output_history.setdefault(key, set()).add(turn["model_output_sha256"])
    verdict_drift = sum(len(values) > 1 for values in verdict_history.values())

    by_phase = {phase["phase"]: phase for phase in phases}
    paired: list[dict[str, Any]] = []
    for scheduled in expected:
        if scheduled["condition"] != "CPU_LOAD":
            continue
        block = scheduled["block"]
        lane = scheduled["stress_lane"]
        loaded = by_phase[scheduled["phase"]]
        baseline_phases = [
            by_phase[f"block-{block}-baseline-pre"],
            by_phase[f"block-{block}-baseline-post"],
        ]
        baseline_by_key: dict[tuple[int, str, str], list[dict[str, Any]]] = {}
        for baseline_phase in baseline_phases:
            for turn in baseline_phase["turns"]:
                baseline_by_key.setdefault(_turn_key(turn), []).append(turn)
        for turn in loaded["turns"]:
            key = _turn_key(turn)
            baseline_turns = baseline_by_key.get(key, [])
            if len(baseline_turns) != 2:
                raise ValueError("RESOURCE_MATRIX_BASELINE_PAIR_MISSING")
            baseline_latency = sum(item["controller_latency_us"] for item in baseline_turns) / 2
            loaded_latency = turn["controller_latency_us"]
            paired.append(
                {
                    "block": block,
                    "stress_lane": lane,
                    "observed_lane": turn["lane"],
                    "record_id_sha256": turn["record_id_sha256"],
                    "prompt_sha256": turn["prompt_sha256"],
                    "baseline_verdicts": [item["verdict"] for item in baseline_turns],
                    "loaded_verdict": turn["verdict"],
                    "verdict_stable": all(item["verdict"] == turn["verdict"] for item in baseline_turns),
                    "baseline_controller_latency_us_mean": round(baseline_latency, 3),
                    "loaded_controller_latency_us": loaded_latency,
                    "controller_latency_change_percent": round(
                        (loaded_latency / baseline_latency - 1) * 100, 3
                    )
                    if baseline_latency > 0
                    else None,
                    "baseline_model_latency_us": [item.get("model_latency_us") for item in baseline_turns],
                    "loaded_model_latency_us": turn.get("model_latency_us"),
                    "loaded_execution": turn["model_execution"],
                }
            )
    effects: dict[str, list[float]] = {}
    for item in paired:
        if item["observed_lane"] == item["stress_lane"] and item["controller_latency_change_percent"] is not None:
            key = f"lane-{item['stress_lane']}:{item['record_id_sha256']}"
            effects.setdefault(key, []).append(item["controller_latency_change_percent"])
    repeat_summary = []
    for key, values in sorted(effects.items()):
        repeat_summary.append(
            {
                "case_key": key,
                "replicate_count": len(values),
                "median_change_percent": round(sorted(values)[len(values) // 2], 3),
                "min_change_percent": round(min(values), 3),
                "max_change_percent": round(max(values), 3),
                "sample_sd_percent": round(
                    (sum((value - sum(values) / len(values)) ** 2 for value in values) / (len(values) - 1)) ** 0.5,
                    3,
                )
                if len(values) > 1
                else None,
            }
        )
    stressors = [phase.get("burner") for phase in phases if phase["condition"] == "CPU_LOAD"]
    load_detected = all(
        isinstance(item, dict) and item.get("load_detected") is True for item in stressors
    )
    stable = verdict_drift == 0 and all(item["verdict_stable"] for item in paired)
    stressed_pairs = [item for item in paired if item["observed_lane"] == item["stress_lane"]]
    within_ten_percent = sum(
        item["controller_latency_change_percent"] is not None
        and abs(item["controller_latency_change_percent"]) < 10
        for item in stressed_pairs
    )
    return {
        "result": "CPU_VERDICT_LATENCY_PAIRED" if load_detected and stable else "INCONCLUSIVE_OR_VERDICT_DRIFT",
        "phase_count": len(phases),
        "baseline_phase_count": sum(phase["condition"] == "BASELINE" for phase in phases),
        "cpu_load_phase_count": sum(phase["condition"] == "CPU_LOAD" for phase in phases),
        "turn_count": sum(len(phase["turns"]) for phase in phases),
        "model_inference_count": sum(
            turn["model_execution"] == "EXECUTED"
            for phase in phases
            for turn in phase["turns"]
        ),
        "paired_latency_observation_count": len(paired),
        "stressed_lane_pairs_with_latency_change_under_10_percent": within_ten_percent,
        "stressed_lane_pair_count": len(stressed_pairs),
        "defense_verdicts_observed": True,
        "verdict_case_count": len(verdict_history),
        "verdict_drift_case_count": verdict_drift,
        "verdicts_stable_across_matched_trials": stable,
        "cpu_load_detected_in_all_arms": load_detected,
        "latency_effect_uncertainty": "Three block replicates per stressed lane and case; report median, range and sample SD. Descriptive only; no population interval or fairness guarantee.",
        "stressed_lane_latency_repeat_summary": repeat_summary,
        "paired_latency_rows": paired,
        "real_model_output_hash_cardinality": {
            key[1]: len(values) for key, values in output_history.items()
        },
        "ram_pid_io_contention_applied": False,
        "host_or_hypervisor_cpu_exclusivity_verified": False,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


class PhaseCapture:
    def __init__(self, scheduled: dict[str, Any], output: Path):
        self.scheduled = scheduled
        self.output = output
        self.runtime: ThreeLaneRuntime | None = None
        self.burner: str | None = None
        self.burner_name: str | None = None
        self.turns: list[dict[str, Any]] = []
        self.window_lock = asyncio.Lock()
        self.window_started = False
        self.window_finished = False
        self.window_start_ns: int | None = None
        self.window_end_ns: int | None = None
        self.model_before: list[dict[str, Any]] | None = None
        self.model_after: list[dict[str, Any]] | None = None
        self.burner_before: dict[str, Any] | None = None
        self.burner_after: dict[str, Any] | None = None
        self.cli_summary: dict[str, Any] | None = None
        self.counter_deltas: dict[str, Any] = {}

    async def begin_window(self) -> None:
        async with self.window_lock:
            if self.window_started:
                return
            if self.runtime is None:
                raise RuntimeError("N05_RUNTIME_NOT_CAPTURED")
            before = await asyncio.to_thread(self.read_cgroups)
            self.model_before = before["models"]
            self.burner_before = before["burner"]
            self.window_start_ns = time.monotonic_ns()
            self.window_started = True

    def read_cgroups(self) -> dict[str, Any]:
        if self.runtime is None:
            raise RuntimeError("N05_RUNTIME_NOT_CAPTURED")
        models = [cgroup_snapshot(cell.container) for cell in self.runtime.cells]
        for lane, snapshot in enumerate(models):
            validate_effective_cgroups(
                snapshot,
                cpuset=self.runtime.admission.model_cpusets[lane],
                memory_bytes=2 * 1024 * 1024 * 1024,
                pids=128,
            )
        burner = cgroup_snapshot(self.burner, python_image=True) if self.burner else None
        if burner is not None:
            validate_effective_cgroups(
                burner,
                cpuset=self.runtime.admission.model_cpusets[self.scheduled["stress_lane"]],
                memory_bytes=256 * 1024 * 1024,
                pids=32,
            )
        return {"models": models, "burner": burner}

    async def finish_window(self) -> None:
        async with self.window_lock:
            if self.window_finished or len(self.turns) != TURNS_PER_PHASE:
                return
            after = await asyncio.to_thread(self.read_cgroups)
            self.model_after = after["models"]
            self.burner_after = after["burner"]
            self.window_end_ns = time.monotonic_ns()
            if self.model_before is None or self.model_after is None:
                raise RuntimeError("RESOURCE_WINDOW_CGROUPS_MISSING")
            for lane in range(3):
                self.counter_deltas[str(lane)] = counter_delta(
                    self.model_before[lane], self.model_after[lane]
                )
            if self.burner_before is not None and self.burner_after is not None:
                self.counter_deltas["burner"] = counter_delta(
                    self.burner_before, self.burner_after
                )
            self.window_finished = True

    def json_phase(self) -> dict[str, Any]:
        if not self.window_finished or self.window_start_ns is None or self.window_end_ns is None:
            raise RuntimeError("RESOURCE_WINDOW_INCOMPLETE")
        elapsed_us = max(1, (self.window_end_ns - self.window_start_ns) // 1000)
        burner_info = None
        if self.burner_name is not None:
            cpu_usec = self.counter_deltas["burner"].get("cpu_stat", {}).get("usage_usec", 0)
            cores = round(cpu_usec / elapsed_us, 6)
            burner_info = {
                "container_name_sha256": sha256(self.burner_name.encode("ascii")),
                "cpuset_cpus": self.runtime.admission.model_cpusets[self.scheduled["stress_lane"]],
                "cpu_quota_cores": 2,
                "memory_limit_bytes": 256 * 1024 * 1024,
                "pids_limit": 32,
                "network_mode": "none",
                "nonroot_readonly_capdrop_no_new_privileges": True,
                "cgroup_delta": self.counter_deltas["burner"],
                "cpu_cores_used": cores,
                "load_detected": cores >= MINIMUM_STRESSOR_CPU_CORES,
            }
        model_trace = (
            self.runtime.model.trace if self.runtime and self.runtime.model else []
        )
        measured_traces = measured_model_traces(self.turns, model_trace)
        return {
            **self.scheduled,
            "result": "MEASURED",
            "runtime_scope": "N05_THREE_PROCESS_BASELINE",
            "host_cpu_exclusivity_verified": False,
            "fairness_measured_by_runtime": False,
            "model_cpusets": list(self.runtime.admission.model_cpusets),
            "resource_window_elapsed_us": elapsed_us,
            "model_cgroup_delta": {
                str(lane): self.counter_deltas[str(lane)] for lane in range(3)
            },
            "burner": burner_info,
            "model_overlap": model_overlap_summary(measured_traces),
            "model_overlap_scope": "N04_CONTROLLER_TURNS_ONLY; N05_STARTUP_CONFORMANCE_TRACES_EXCLUDED",
            "turns": sorted(self.turns, key=lambda item: (item["lane"], item["record_id_sha256"])),
            "n04_cli": {
                "run_label": self.cli_summary["run_label"],
                "turn_count": self.cli_summary["turns"],
                "model_dispatches": self.cli_summary["model_dispatches"],
                "verifier_exit_code": self.cli_summary["verifier_exit_code"],
                "verifier_status": self.cli_summary["verifier_result"]["status"],
                "three_lane_acceptance": self.cli_summary["three_lane_acceptance"],
            },
        }

    def partial_json(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            **self.scheduled,
            "result": "INCOMPLETE_RETAINED",
            "runtime_scope": "N05_THREE_PROCESS_BASELINE",
            "host_cpu_exclusivity_verified": False,
            "fairness_measured_by_runtime": False,
            "turns_observed_before_failure": len(self.turns),
            "turns": sorted(self.turns, key=lambda item: (item["lane"], item["record_id_sha256"])),
            "resource_window_started": self.window_started,
            "resource_window_finished": self.window_finished,
            "burner_started": self.burner_name is not None,
            "burner_cleanup_completed": self.burner is None,
        }
        if self.runtime is not None and self.runtime.model is not None:
            value["model_overlap"] = model_overlap_summary(self.runtime.model.trace)
        return value


class MatrixRunner:
    def __init__(self, *, lock: Path, model: Path, corpus: Path, corpus_receipt: Path, corpus_keys: Path):
        self.lock, self.model, self.corpus = lock, model, corpus
        self.corpus_receipt, self.corpus_keys = corpus_receipt, corpus_keys
        self.phase: PhaseCapture | None = None
        self.originals: dict[str, Any] = {}

    def install(self) -> None:
        self.originals = {
            "start": ThreeLaneRuntime.start,
            "stop": ThreeLaneRuntime.stop,
            "turn": N04Controller.turn,
            "defend": N04Controller._defend,
        }
        original_start = self.originals["start"]
        original_stop = self.originals["stop"]
        original_turn = self.originals["turn"]
        original_defend = self.originals["defend"]

        def start(runtime: ThreeLaneRuntime):
            inspection = original_start(runtime)
            phase = self.phase
            if phase is None:
                raise RuntimeError("RESOURCE_PHASE_NOT_SET")
            phase.runtime = runtime
            check_model_limits(runtime, inspection)
            if phase.scheduled["stress_lane"] is not None:
                lane = phase.scheduled["stress_lane"]
                phase.burner = start_burner(
                    runtime.lock["defense_image"], runtime.admission.model_cpusets[lane]
                )
                phase.burner_name = phase.burner
            original_infer = runtime.model.infer

            async def tracked_infer(request):
                sample = _CURRENT_TURN.get()
                response = await original_infer(request)
                if sample is not None:
                    if sample.get("model") is not None:
                        raise RuntimeError("MULTIPLE_MODEL_RESPONSES_FOR_TURN")
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

        def stop(runtime: ThreeLaneRuntime):
            phase = self.phase
            try:
                if phase is not None and phase.burner is not None:
                    burner = phase.burner
                    phase.burner = None
                    remove_owned_container(burner)
            finally:
                original_stop(runtime)

        async def defend(controller: N04Controller, request):
            decision = await original_defend(controller, request)
            sample = _CURRENT_TURN.get()
            if sample is not None:
                if sample.get("verdict") is not None:
                    raise RuntimeError("MULTIPLE_DEFENSE_DECISIONS_FOR_TURN")
                sample["verdict"] = decision.verdict
            return decision

        async def turn(controller: N04Controller, principal, session_id, request, key, payload):
            phase = self.phase
            sample = {
                "record_id_sha256": sha256(payload.provenance.record_id.encode("utf-8")),
                "prompt_sha256": sha256(payload.text.encode("utf-8")),
                "payload_reference_sha256": sha256(payload.payload_ref.encode("ascii")),
                "turn_index": request.turn_index,
                "model": None,
                "verdict": None,
            }
            token = _CURRENT_TURN.set(sample)
            try:
                if phase is None:
                    raise RuntimeError("RESOURCE_PHASE_NOT_SET")
                await phase.begin_window()
                started_ns = time.perf_counter_ns()
                result = await original_turn(controller, principal, session_id, request, key, payload)
                controller_latency_us = max(1, (time.perf_counter_ns() - started_ns) // 1000)
                if sample["verdict"] is None:
                    # The CLI's exact idempotent replay returns before invoking defense.
                    return result
                events = [
                    event
                    for event in controller.recorder.get_events(controller.ctx)
                    if event.turn_id == result.turn_id and event.event_type == "DEFENSE_RESULT"
                ]
                if len(events) != 1 or events[0].outcome_code != sample["verdict"]:
                    raise RuntimeError("DEFENSE_EVENT_VERDICT_PAIR_MISMATCH")
                lane_name = controller.runtime.model.get_assigned_lane(session_id)
                match = re.fullmatch(r"lane-([0-2])", lane_name or "")
                if match is None:
                    raise RuntimeError("TURN_LANE_BINDING_MISSING")
                lane = int(match.group(1))
                disposition = result.result.pipeline_disposition
                expected_disposition = {
                    "ALLOW": "ALLOWED",
                    "BLOCK": "BLOCKED_BY_DEFENSE",
                    "SANITIZE": "SANITIZED",
                }[sample["verdict"]]
                if disposition != expected_disposition:
                    raise RuntimeError("DEFENSE_VERDICT_DISPOSITION_MISMATCH")
                model = sample["model"]
                if (result.result.model_execution == "EXECUTED") != (model is not None):
                    raise RuntimeError("MODEL_EXECUTION_TRACE_MISMATCH")
                phase.turns.append(
                    {
                        "lane": lane,
                        "record_id_sha256": sample["record_id_sha256"],
                        "prompt_sha256": sample["prompt_sha256"],
                        "payload_reference_sha256": sample["payload_reference_sha256"],
                        "turn_index": sample["turn_index"],
                        "turn_id_sha256": sha256(result.turn_id.encode("ascii")),
                        "verdict": sample["verdict"],
                        "defense_event_outcome": events[0].outcome_code,
                        "pipeline_disposition": disposition,
                        "model_execution": result.result.model_execution,
                        "controller_latency_us": controller_latency_us,
                        "model_latency_us": model["duration_us"] if model else None,
                        "model_input_tokens": model["input_tokens"] if model else None,
                        "model_output_tokens": model["output_tokens"] if model else None,
                        "model_output_sha256": model["output_sha256"] if model else None,
                    }
                )
                if len(phase.turns) > TURNS_PER_PHASE:
                    raise RuntimeError("RESOURCE_MATRIX_TURN_COUNT_EXCEEDED")
                await phase.finish_window()
                return result
            finally:
                _CURRENT_TURN.reset(token)

        ThreeLaneRuntime.start = start
        ThreeLaneRuntime.stop = stop
        N04Controller.turn = turn
        N04Controller._defend = defend

    def restore(self) -> None:
        if not self.originals:
            return
        ThreeLaneRuntime.start = self.originals["start"]
        ThreeLaneRuntime.stop = self.originals["stop"]
        N04Controller.turn = self.originals["turn"]
        N04Controller._defend = self.originals["defend"]
        self.originals.clear()

    async def run_phase(self, scheduled: dict[str, Any], output: Path) -> dict[str, Any]:
        self.phase = PhaseCapture(scheduled, output)
        args = SimpleNamespace(
            lock=self.lock,
            model=self.model,
            corpus=self.corpus,
            corpus_receipt=self.corpus_receipt,
            corpus_keys=self.corpus_keys,
            output=output,
            mode="INPUT",
            traffic="real",
            lanes=3,
            n06_policy=None,
            n06_policy_public_key=None,
            n06_policy_key_id=None,
            n06_local_mtls=False,
            n06_sealed_profile=False,
            n06_workload="six",
        )
        return_code = await asyncio.wait_for(
            run_n04_cli(args), timeout=PHASE_TIMEOUT_SECONDS
        )
        if return_code != 0:
            raise RuntimeError("N04_CLI_RUN_FAILED")
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        if (
            summary.get("run_label") != "REAL_PUBLIC"
            or summary.get("turns") != TURNS_PER_PHASE
            or summary.get("verifier_exit_code") != 0
            or summary.get("verifier_result", {}).get("status") != "PASS_PUBLIC_EVIDENCE"
            or summary.get("lane_count") != 3
        ):
            raise RuntimeError("N04_CLI_RUN_ACCEPTANCE_MISMATCH")
        if self.phase.cli_summary is not None:
            raise RuntimeError("N04_CLI_SUMMARY_ALREADY_SET")
        self.phase.cli_summary = summary
        if len(self.phase.turns) != TURNS_PER_PHASE or not self.phase.window_finished:
            raise RuntimeError("N04_TURN_OBSERVATIONS_INCOMPLETE")
        phase_value = self.phase.json_phase()
        if summary["model_dispatches"] != sum(
            turn["model_execution"] == "EXECUTED" for turn in phase_value["turns"]
        ):
            raise RuntimeError("N04_DISPATCH_COUNT_MISMATCH")
        measured_traces = measured_model_traces(
            phase_value["turns"], summary.get("model_trace", [])
        )
        phase_value["model_overlap"] = model_overlap_summary(measured_traces)
        phase_value[
            "model_overlap_scope"
        ] = "N04_CONTROLLER_TURNS_ONLY; N05_STARTUP_CONFORMANCE_TRACES_EXCLUDED"
        if len(running_containers()) != 0:
            raise RuntimeError("OWNED_PHASE_LEFT_RUNNING_CONTAINERS")
        return phase_value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "model", "corpus", "corpus-receipt", "corpus-keys", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    lock, model, corpus = args.lock.resolve(), args.model.resolve(), args.corpus.resolve()
    receipt, keys, output = (
        args.corpus_receipt.resolve(),
        args.corpus_keys.resolve(),
        args.output.resolve(),
    )
    if not all(path.is_file() for path in (lock, model, receipt, keys)):
        raise FileNotFoundError("ADMITTED_LOCAL_MODEL_OR_CORPUS_INPUT_MISSING")
    if not corpus.is_dir():
        raise FileNotFoundError("PREPARED_PUBLIC_CORPUS_DIRECTORY_MISSING")
    if not output.is_relative_to(ARTIFACTS.resolve()) or output.exists():
        raise ValueError("NEW_PRIVATE_OUTPUT_DIRECTORY_REQUIRED_UNDER_BACKEND_ARTIFACTS")
    output.mkdir(parents=True, exist_ok=False)
    result: dict[str, Any] = {
        "schema_version": "arena-n07b-resource-fairness-verdict-matrix.v1",
        "scope": SCOPE,
        "result": "INCONCLUSIVE",
        "real_inference_performed": False,
        "real_public_jbb_used": False,
        "defense_verdicts_observed": False,
        "ram_pid_io_contention_applied": False,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
        "lock_sha256": digest_file(lock),
        "model_sha256": digest_file(model),
        "corpus_receipt_sha256": digest_file(receipt),
    }
    phases: list[dict[str, Any]] = []
    runner = MatrixRunner(
        lock=lock,
        model=model,
        corpus=corpus,
        corpus_receipt=receipt,
        corpus_keys=keys,
    )
    try:
        ensure_local_docker()
        existing = running_containers()
        if existing:
            result["failure_code"] = "PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED"
            result["preexisting_running_container_count"] = len(existing)
            result["preexisting_running_container_name_sha256"] = sorted(
                sha256(name.encode("utf-8")) for name in existing
            )
            raise RuntimeError("PREEXISTING_RUNNING_CONTAINERS_LEFT_UNTOUCHED")
        from arena.contracts.jsonwire import load_wire
        from arena.integration.lanes import LaneAdmission

        admission = load_wire(LaneAdmission, lock.read_bytes())
        preflight_burner(admission.defense_image)
        runner.install()
        for scheduled in phase_plan():
            phase_output = output / scheduled["phase"]
            try:
                phase = asyncio.run(await_phase(runner, scheduled, phase_output))
            except BaseException:
                if runner.phase is not None:
                    phases.append(runner.phase.partial_json())
                raise
            phases.append(phase)
        summary = analyze_phases(phases)
        result.update(
            {
                "result": summary["result"],
                "real_inference_performed": True,
                "real_public_jbb_used": True,
                "defense_verdicts_observed": True,
                "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M",
                "phase_plan": phase_plan(),
                "phases": phases,
                "summary": summary,
                "phase_count": len(phases),
                "baseline_phase_count": summary["baseline_phase_count"],
                "cpu_load_phase_count": summary["cpu_load_phase_count"],
                "turn_count": summary["turn_count"],
                "model_inference_count": summary["model_inference_count"],
                "selected_record_source": "JBB-Behaviors/REAL_PUBLIC; selected internally by N04 CLI",
                "runtime_downloads": False,
                "ram_pid_io_contention_applied": False,
                "p011_complete": False,
                "p013_complete": False,
                "full_n07_acceptance": False,
                "full_arena_acceptance": False,
                "guarantee_tier_achieved": None,
            }
        )
        return_code = 0 if summary["result"] == "CPU_VERDICT_LATENCY_PAIRED" else 2
    except BaseException as exc:
        result["result"] = "INCONCLUSIVE"
        failure = "PROBE_EXCEPTION_" + type(exc).__name__
        message = str(exc)
        if isinstance(exc, RuntimeError) and re.fullmatch(r"[A-Z0-9_]+", message):
            failure += ":" + message
        result.setdefault("failure_code", failure)
        result["partial_phases"] = phases
        return_code = 1
    finally:
        runner.restore()
    (output / "observation.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary = result.get("summary", {})
    print(
        json.dumps(
            {
                "result": result["result"],
                "scope": SCOPE,
                "phase_count": result.get("phase_count", len(phases)),
                "turn_count": result.get("turn_count"),
                "model_inference_count": result.get("model_inference_count"),
                "verdict_drift_case_count": summary.get("verdict_drift_case_count"),
                "cpu_load_detected_in_all_arms": summary.get("cpu_load_detected_in_all_arms"),
                "ram_pid_io_contention_applied": False,
                "p011_complete": False,
                "p013_complete": False,
                "full_n07_acceptance": False,
                "guarantee_tier_achieved": None,
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return return_code


async def await_phase(runner: MatrixRunner, scheduled: dict[str, Any], output: Path) -> dict[str, Any]:
    stdout = io.StringIO()
    try:
        with redirect_stdout(stdout):
            return await runner.run_phase(scheduled, output)
    finally:
        output.mkdir(parents=True, exist_ok=True)
        (output / "n04-cli-stdout.log").write_text(stdout.getvalue(), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
