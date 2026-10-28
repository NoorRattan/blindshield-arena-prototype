"""Collect source-bound evidence for the bounded N07B CPU-load probe.

Runs actual local Qwen over already-admitted public JBB inputs, then preserves
the normal backend regression/conformance checks. The result is CPU-only model
throughput evidence, not a defense-verdict, RAM/PID/I/O, or full P-011 claim.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from verify_n04 import sources as backend_sources


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
EVIDENCE = ROOT / "memory files" / "hackathon" / "evidence"
N06_RECEIPT = EVIDENCE / "n06-completion-verification-2026-10-22.json"
N07A_RECEIPT = EVIDENCE / "n07-review-verification-2026-10-24.json"
INITIAL_ATTEMPT = EVIDENCE / "n07b-resource-fairness-2026-10-24-mem031.json"
INITIAL_ATTEMPT_OUTPUTS = INITIAL_ATTEMPT.with_name(INITIAL_ATTEMPT.stem + "-outputs.json")
STALE_REPORT_ATTEMPT = EVIDENCE / "n07b-resource-fairness-2026-10-24-mem031-final.json"
STALE_REPORT_OUTPUTS = STALE_REPORT_ATTEMPT.with_name(STALE_REPORT_ATTEMPT.stem + "-outputs.json")
VALIDATION_ATTEMPT = EVIDENCE / "n07b-resource-fairness-2026-10-24-mem031-verified.json"
VALIDATION_OUTPUTS = VALIDATION_ATTEMPT.with_name(VALIDATION_ATTEMPT.stem + "-outputs.json")
SCOPE = "N07B_BOUNDED_REAL_LOCAL_CPU_LOAD_RESOURCE_OBSERVATION"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def source_hashes() -> dict[str, str]:
    files = backend_sources()
    files["tools/check_memory.py"] = digest(ROOT / "tools/check_memory.py")
    return files


def historical_source_matches(relative: str, expected: str) -> bool:
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        return False
    if digest(path) == expected:
        return True
    snapshot = BACKEND / "evidence" / "source-snapshots" / (expected + ".txt")
    return snapshot.is_file() and digest(snapshot) == expected


def historical_receipt_matches(path: Path) -> bool:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    sources = receipt.get("source_sha256", {})
    return bool(sources) and all(
        historical_source_matches(relative, expected)
        for relative, expected in sources.items()
    )


def preserved_initial_attempt() -> dict[str, Any]:
    if not INITIAL_ATTEMPT.is_file() or not INITIAL_ATTEMPT_OUTPUTS.is_file():
        raise ValueError("PRESERVED_INITIAL_ATTEMPT_EVIDENCE_MISSING")
    receipt = json.loads(INITIAL_ATTEMPT.read_bytes())
    outputs = json.loads(INITIAL_ATTEMPT_OUTPUTS.read_bytes())
    if (
        receipt.get("schema_version") != "arena-n07b-resource-fairness.v1"
        or receipt.get("scope") != SCOPE
        or receipt.get("result") != "FAIL"
        or receipt.get("collector_state") != "FAILED"
        or receipt.get("base_commit") != subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        or not historical_receipt_matches(INITIAL_ATTEMPT)
        or outputs.get("receipt") != INITIAL_ATTEMPT.relative_to(ROOT).as_posix()
        or outputs.get("receipt_sha256") != digest(INITIAL_ATTEMPT)
        or outputs.get("schema_version") != "arena-n07b-resource-fairness.v1"
    ):
        raise ValueError("PRESERVED_INITIAL_ATTEMPT_BINDING_INVALID")
    commands = receipt.get("command_results", [])
    if (
        len(commands) != 2
        or [item.get("name") for item in commands] != ["prepare-n05", "resource-fairness-probe"]
        or commands[0].get("exit_code") != 0
        or commands[1].get("exit_code") != 1
        or commands[1].get("accepted_exit_codes") != [0, 2]
        or receipt.get("failure") != "RuntimeError:REQUIRED_COMMAND_FAILED_RESOURCE_FAIRNESS_PROBE"
    ):
        raise ValueError("PRESERVED_INITIAL_ATTEMPT_RESULT_INVALID")

    paths: dict[str, Path] = {"receipt": INITIAL_ATTEMPT, "outputs_index": INITIAL_ATTEMPT_OUTPUTS}
    for command in commands:
        path = (ROOT / command["log_path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or digest(path) != command.get("log_sha256"):
            raise ValueError("PRESERVED_INITIAL_ATTEMPT_LOG_HASH_MISMATCH")
        paths[command["name"] + "_log"] = path
    for name, item in outputs.get("files", {}).items():
        path = (ROOT / item["path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or digest(path) != item.get("sha256"):
            raise ValueError("PRESERVED_INITIAL_ATTEMPT_OUTPUT_HASH_MISMATCH")
        if name not in {command["name"] for command in commands}:
            raise ValueError("PRESERVED_INITIAL_ATTEMPT_OUTPUT_INDEX_UNEXPECTED")

    private_relative = receipt.get("private_artifacts", {}).get("runtime_output", "")
    private_root = (BACKEND / private_relative).resolve()
    private_observation = private_root / "observation.json"
    if not private_root.is_relative_to((BACKEND / "artifacts").resolve()) or not private_observation.is_file():
        raise ValueError("PRESERVED_INITIAL_PRIVATE_OBSERVATION_MISSING")
    observed = json.loads(private_observation.read_bytes())
    phases = observed.get("partial_phases", [])
    if (
        observed.get("result") != "INCONCLUSIVE"
        or observed.get("failure_code") != "PROBE_EXCEPTION_DependencyUnavailable"
        or len(phases) != 1
        or phases[0].get("phase") != "baseline-pre"
        or [lane.get("call_count") for lane in phases[0].get("lanes", [])] != [4, 4, 4]
        or len(observed.get("selected_public_records", [])) != 4
    ):
        raise ValueError("PRESERVED_INITIAL_PRIVATE_OBSERVATION_RESULT_INVALID")

    return {
        "result": "FAILED_INITIAL_HARNESS_ATTEMPT_PRESERVED",
        "note": "Baseline completed; the first CPU-load control did not start because its process limit blocked Docker exec. The process limit was corrected before the final attempt.",
        "receipt_path": INITIAL_ATTEMPT.relative_to(ROOT).as_posix(),
        "receipt_sha256": digest(INITIAL_ATTEMPT),
        "outputs_index_path": INITIAL_ATTEMPT_OUTPUTS.relative_to(ROOT).as_posix(),
        "outputs_index_sha256": digest(INITIAL_ATTEMPT_OUTPUTS),
        "prepare_log_path": paths["prepare-n05_log"].relative_to(ROOT).as_posix(),
        "prepare_log_sha256": digest(paths["prepare-n05_log"]),
        "probe_log_path": paths["resource-fairness-probe_log"].relative_to(ROOT).as_posix(),
        "probe_log_sha256": digest(paths["resource-fairness-probe_log"]),
        "private_observation_path": private_observation.relative_to(ROOT).as_posix(),
        "private_observation_sha256": digest(private_observation),
        "private_observation_committed": False,
        "completed_baseline_phase_count": 1,
        "completed_baseline_model_calls": 12,
        "cpu_load_phases_completed": 0,
        "failure_code": observed["failure_code"],
        "historical_source_hashes_match": True,
    }


def preserved_stale_report_attempt() -> dict[str, Any]:
    if not STALE_REPORT_ATTEMPT.is_file() or not STALE_REPORT_OUTPUTS.is_file():
        raise ValueError("PRESERVED_STALE_REPORT_ATTEMPT_EVIDENCE_MISSING")
    receipt = json.loads(STALE_REPORT_ATTEMPT.read_bytes())
    outputs = json.loads(STALE_REPORT_OUTPUTS.read_bytes())
    if (
        receipt.get("schema_version") != "arena-n07b-resource-fairness.v1"
        or receipt.get("scope") != SCOPE
        or receipt.get("result") != "COLLECTION_FAILED"
        or receipt.get("collector_state") != "FAILED"
        or receipt.get("failure") != "RuntimeError:REQUIRED_COMMAND_FAILED_MEMORY_CHECK_PRE_RECONCILIATION"
        or not historical_receipt_matches(STALE_REPORT_ATTEMPT)
        or outputs.get("receipt") != STALE_REPORT_ATTEMPT.relative_to(ROOT).as_posix()
        or outputs.get("receipt_sha256") != digest(STALE_REPORT_ATTEMPT)
    ):
        raise ValueError("PRESERVED_STALE_REPORT_ATTEMPT_BINDING_INVALID")
    commands = receipt.get("command_results", [])
    names = [item.get("name") for item in commands]
    if (
        names != [
            "prepare-n05", "resource-fairness-probe", "pytest-primary", "pytest-offline",
            "schemas", "vectors", "control-smoke", "contract-smoke", "dependencies",
            "memory-check-pre-reconciliation",
        ]
        or [item.get("exit_code") for item in commands[:-1]] != [0] * 9
        or commands[-1].get("exit_code") != 1
        or receipt.get("source_file_count") != 169
    ):
        raise ValueError("PRESERVED_STALE_REPORT_ATTEMPT_RESULT_INVALID")
    for command in commands:
        path = (ROOT / command["log_path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or digest(path) != command.get("log_sha256"):
            raise ValueError("PRESERVED_STALE_REPORT_ATTEMPT_LOG_HASH_MISMATCH")
    for item in outputs.get("files", {}).values():
        path = (ROOT / item["path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or digest(path) != item.get("sha256"):
            raise ValueError("PRESERVED_STALE_REPORT_ATTEMPT_OUTPUT_HASH_MISMATCH")

    private_relative = receipt.get("private_artifacts", {}).get("runtime_output", "")
    private_root = (BACKEND / private_relative).resolve()
    private_observation = private_root / "observation.json"
    if not private_root.is_relative_to((BACKEND / "artifacts").resolve()) or not private_observation.is_file():
        raise ValueError("PRESERVED_STALE_REPORT_PRIVATE_OBSERVATION_MISSING")
    observed = json.loads(private_observation.read_bytes())
    probe = next((item for item in commands if item["name"] == "resource-fairness-probe"), None)
    if (
        observed.get("result") != "CPU_LOAD_APPLIED"
        or observed.get("total_model_calls") != 60
        or observed.get("phase_count") != 5
        or not probe
        or probe.get("exit_code") != 0
    ):
        raise ValueError("PRESERVED_STALE_REPORT_PRIVATE_OBSERVATION_INVALID")
    return {
        "result": "FAILED_COLLECTION_STALE_MEMORY_REPORT",
        "note": "Probe, both full test suites and all backend checks passed; the collector stopped because the memory verification report did not yet include the new source snapshots.",
        "receipt_path": STALE_REPORT_ATTEMPT.relative_to(ROOT).as_posix(),
        "receipt_sha256": digest(STALE_REPORT_ATTEMPT),
        "outputs_index_path": STALE_REPORT_OUTPUTS.relative_to(ROOT).as_posix(),
        "outputs_index_sha256": digest(STALE_REPORT_OUTPUTS),
        "prepare_log_path": commands[0]["log_path"],
        "prepare_log_sha256": commands[0]["log_sha256"],
        "probe_log_path": commands[1]["log_path"],
        "probe_log_sha256": commands[1]["log_sha256"],
        "private_observation_path": private_observation.relative_to(ROOT).as_posix(),
        "private_observation_sha256": digest(private_observation),
        "private_observation_committed": False,
        "measurement_result": observed["result"],
        "completed_model_calls": observed["total_model_calls"],
        "primary_pytest_count": 389,
        "offline_pytest_count": 389,
        "backend_commands_before_memory_report": 9,
    }


def preserved_validation_attempt() -> dict[str, Any]:
    if not VALIDATION_ATTEMPT.is_file() or not VALIDATION_OUTPUTS.is_file():
        raise ValueError("PRESERVED_VALIDATION_ATTEMPT_EVIDENCE_MISSING")
    receipt = json.loads(VALIDATION_ATTEMPT.read_bytes())
    outputs = json.loads(VALIDATION_OUTPUTS.read_bytes())
    if (
        receipt.get("schema_version") != "arena-n07b-resource-fairness.v1"
        or receipt.get("scope") != SCOPE
        or receipt.get("result") != "COLLECTION_FAILED"
        or receipt.get("collector_state") != "FAILED"
        or receipt.get("failure") != "ValueError:RESOURCE_FAIRNESS_LANE_METRICS_INVALID"
        or not historical_receipt_matches(VALIDATION_ATTEMPT)
        or outputs.get("receipt") != VALIDATION_ATTEMPT.relative_to(ROOT).as_posix()
        or outputs.get("receipt_sha256") != digest(VALIDATION_ATTEMPT)
        or receipt.get("source_file_count") != 169
    ):
        raise ValueError("PRESERVED_VALIDATION_ATTEMPT_BINDING_INVALID")
    commands = receipt.get("command_results", [])
    names = [item.get("name") for item in commands]
    expected_names = [
        "prepare-n05", "resource-fairness-probe", "pytest-primary", "pytest-offline",
        "schemas", "vectors", "control-smoke", "contract-smoke", "dependencies",
        "memory-check-pre-reconciliation",
    ]
    if names != expected_names or any(item.get("exit_code") != 0 for item in commands):
        raise ValueError("PRESERVED_VALIDATION_ATTEMPT_COMMANDS_INVALID")
    for command in commands:
        path = (ROOT / command["log_path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or digest(path) != command.get("log_sha256"):
            raise ValueError("PRESERVED_VALIDATION_ATTEMPT_LOG_HASH_MISMATCH")
    for item in outputs.get("files", {}).values():
        path = (ROOT / item["path"]).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or digest(path) != item.get("sha256"):
            raise ValueError("PRESERVED_VALIDATION_ATTEMPT_OUTPUT_HASH_MISMATCH")

    private_relative = receipt.get("private_artifacts", {}).get("runtime_output", "")
    private_root = (BACKEND / private_relative).resolve()
    private_observation = private_root / "observation.json"
    if not private_root.is_relative_to((BACKEND / "artifacts").resolve()) or not private_observation.is_file():
        raise ValueError("PRESERVED_VALIDATION_PRIVATE_OBSERVATION_MISSING")
    observed = json.loads(private_observation.read_bytes())
    validated = validate_observation(observed)
    if validated["result"] != "CPU_LOAD_APPLIED" or validated["total_model_calls"] != 60:
        raise ValueError("PRESERVED_VALIDATION_OBSERVATION_RESULT_INVALID")
    for name in ("pytest-primary", "pytest-offline"):
        summary = next(item["summary"] for item in commands if item["name"] == name)
        if not all(part in summary for part in ("389 passed", "1 skipped", "14 subtests passed")):
            raise ValueError("PRESERVED_VALIDATION_PYTEST_SUMMARY_INVALID")
    return {
        "result": "FAILED_COLLECTOR_CPUSET_FORMAT_VALIDATION_REPLAYED",
        "note": "The probe and all checks completed; the old validator rejected equivalent effective cpusets formatted as ranges. The saved observation now passes set-equivalent CPU normalization and full schema/counter revalidation.",
        "receipt_path": VALIDATION_ATTEMPT.relative_to(ROOT).as_posix(),
        "receipt_sha256": digest(VALIDATION_ATTEMPT),
        "outputs_index_path": VALIDATION_OUTPUTS.relative_to(ROOT).as_posix(),
        "outputs_index_sha256": digest(VALIDATION_OUTPUTS),
        "prepare_log_path": commands[0]["log_path"],
        "prepare_log_sha256": commands[0]["log_sha256"],
        "probe_log_path": commands[1]["log_path"],
        "probe_log_sha256": commands[1]["log_sha256"],
        "private_observation_path": private_observation.relative_to(ROOT).as_posix(),
        "private_observation_sha256": digest(private_observation),
        "private_observation_committed": False,
        "measurement_result": validated["result"],
        "completed_model_calls": validated["total_model_calls"],
        "primary_pytest_count": 389,
        "offline_pytest_count": 389,
        "pre_reconciliation_memory_check": "PASS",
        "normalization_revalidation": "PASS",
    }


def make_outputs_index(receipt_path: Path, receipt: dict[str, Any]) -> Path:
    files = {
        item["name"]: {"path": item["log_path"], "sha256": item["log_sha256"]}
        for item in receipt.get("command_results", [])
    }
    for index, item in enumerate(receipt.get("preliminary_runs", []), start=1):
        for path_key, hash_key, label in (
            ("receipt_path", "receipt_sha256", "receipt"),
            ("outputs_index_path", "outputs_index_sha256", "outputs_index"),
            ("prepare_log_path", "prepare_log_sha256", "prepare_log"),
            ("probe_log_path", "probe_log_sha256", "probe_log"),
            ("private_observation_path", "private_observation_sha256", "private_observation"),
        ):
            if item.get(path_key):
                files[f"preliminary_{index}_{label}"] = {
                    "path": item[path_key], "sha256": item[hash_key]
                }
    if receipt.get("private_observation"):
        files["private_observation"] = receipt["private_observation"]
    path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    atomic_json(
        path,
        {
            "schema_version": "arena-n07b-resource-fairness.v1",
            "receipt": receipt_path.relative_to(ROOT).as_posix(),
            "receipt_sha256": digest(receipt_path),
            "files": files,
        },
    )
    return path


def reject_payload_fields(value: Any) -> None:
    forbidden = {"text", "prompt", "response", "completion", "key_b64", "nonce_b64", "aad_b64"}
    if isinstance(value, dict):
        if forbidden & {str(key).casefold() for key in value}:
            raise ValueError("PRIVATE_OR_MODEL_TEXT_FIELD_IN_OBSERVATION")
        for item in value.values():
            reject_payload_fields(item)
    elif isinstance(value, list):
        for item in value:
            reject_payload_fields(item)


def effective_cpu_quota(cpu_max: str) -> float:
    quota, period = cpu_max.split()
    if not quota.isascii() or not quota.isdecimal() or not period.isascii() or not period.isdecimal() or int(period) <= 0:
        raise ValueError("EFFECTIVE_CPU_QUOTA_INVALID")
    return int(quota) / int(period)


def normalized_cpu_set(value: str) -> frozenset[int]:
    if not isinstance(value, str) or not value:
        raise ValueError("CPUSET_VALUE_INVALID")
    cpus: set[int] = set()
    for part in value.split(","):
        start_text, separator, end_text = part.partition("-")
        if not start_text.isascii() or not start_text.isdecimal():
            raise ValueError("CPUSET_VALUE_INVALID")
        start = int(start_text)
        end = start
        if separator:
            if not end_text.isascii() or not end_text.isdecimal():
                raise ValueError("CPUSET_VALUE_INVALID")
            end = int(end_text)
            if end < start:
                raise ValueError("CPUSET_VALUE_INVALID")
        if end > 8191:
            raise ValueError("CPUSET_VALUE_INVALID")
        cpus.update(range(start, end + 1))
    if not cpus:
        raise ValueError("CPUSET_VALUE_INVALID")
    return frozenset(cpus)


def validate_observation(observed: dict) -> dict:
    reject_payload_fields(observed)
    summary = observed.get("summary", {})
    phases = observed.get("phases", [])
    selected = observed.get("selected_public_records", [])
    permitted_results = {"CPU_LOAD_APPLIED", "INCONCLUSIVE_LOAD_NOT_DETECTED"}
    if (
        observed.get("schema_version") != "arena-n07b-resource-fairness-observation.v1"
        or observed.get("scope") != SCOPE
        or observed.get("result") not in permitted_results
        or observed.get("model_kind") != "REAL_LOCAL_QWEN_0.5B_Q4_K_M"
        or observed.get("real_inference_performed") is not True
        or observed.get("real_public_jbb_used") is not True
        or observed.get("defense_verdicts_observed") is not False
        or observed.get("ram_pid_io_contention_applied") is not False
        or observed.get("full_p011_acceptance") is not False
        or observed.get("full_n07_acceptance") is not False
        or observed.get("full_arena_acceptance") is not False
        or observed.get("guarantee_tier_achieved") is not None
        or observed.get("phase_count") != 5
        or observed.get("model_lane_count") != 3
        or observed.get("calls_per_lane_per_phase") != 4
        or observed.get("total_model_calls") != 60
        or observed.get("selected_records_per_split") != 2
        or observed.get("output_token_cap_per_call") != 32
        or len(phases) != 5
        or len(selected) != 4
        or [item.get("split") for item in selected].count("benign") != 2
        or [item.get("split") for item in selected].count("harmful") != 2
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", item.get(key, ""))
            for item in selected
            for key in ("record_ordinal_sha256", "prompt_sha256", "payload_reference_sha256")
        )
        or summary.get("result") != observed.get("result")
        or summary.get("defense_verdicts_observed") is not False
        or summary.get("ram_pid_io_contention_applied") is not False
        or summary.get("full_p011_acceptance") is not False
        or summary.get("full_n07_acceptance") is not False
        or summary.get("full_arena_acceptance") is not False
        or summary.get("guarantee_tier_achieved") is not None
        or [phase.get("phase") for phase in phases]
        != ["baseline-pre", "cpu-load-lane-0", "cpu-load-lane-1", "cpu-load-lane-2", "baseline-post"]
        or [phase.get("stress_lane") for phase in phases] != [None, 0, 1, 2, None]
    ):
        raise ValueError("RESOURCE_FAIRNESS_OBSERVATION_SCOPE_OR_RESULT_INVALID")
    for phase in phases:
        lanes = phase.get("lanes", [])
        if (
            phase.get("result") != "MEASURED"
            or phase.get("runtime_scope") != "N05_THREE_PROCESS_BASELINE"
            or phase.get("host_cpu_exclusivity_verified") is not False
            or phase.get("fairness_measured_by_runtime") is not False
            or len(lanes) != 3
            or any(
                item.get("lane") != lane
                or item.get("call_count") != 4
                or item.get("output_tokens", 0) > 4 * 32
                or item.get("inference_window_elapsed_us", 0) != phase.get("inference_window_elapsed_us")
                or item.get("output_tokens_per_second", 0) < 0
                for lane, item in enumerate(lanes)
            )
            or phase.get("inference_window_elapsed_us", 0) <= 0
            or phase.get("cgroup_window_elapsed_us", 0) < phase.get("inference_window_elapsed_us", 0)
            or len(phase.get("model_cpusets", [])) != 3
        ):
            raise ValueError("RESOURCE_FAIRNESS_PHASE_INVALID")
        for lane in lanes:
            model_cgroup = lane.get("model_cgroup_delta", {})
            if (
                len(lane.get("calls", [])) != 4
                or lane.get("input_tokens", -1) < 0
                or lane.get("output_tokens", -1) < 0
                or lane.get("output_tokens") != sum(call.get("output_tokens", -1) for call in lane["calls"])
                or lane.get("input_tokens") != sum(call.get("input_tokens", -1) for call in lane["calls"])
                or any(
                    type(call.get("input_tokens")) is not int
                    or call["input_tokens"] < 0
                    or type(call.get("output_tokens")) is not int
                    or not 0 <= call["output_tokens"] <= 32
                    or type(call.get("duration_us")) is not int
                    or call["duration_us"] <= 0
                    or not re.fullmatch(r"[0-9a-f]{64}", call.get("output_sha256", ""))
                    for call in lane["calls"]
                )
                or lane.get("output_tokens_per_second")
                != round(lane["output_tokens"] * 1_000_000 / lane["inference_window_elapsed_us"], 6)
                or model_cgroup.get("cpu_stat", {}).get("usage_usec", -1) < 0
                or effective_cpu_quota(model_cgroup.get("cpu_max", "")) != 2
                or normalized_cpu_set(model_cgroup.get("cpuset_cpus_effective", ""))
                != normalized_cpu_set(phase["model_cpusets"][lane["lane"]])
                or model_cgroup.get("memory_limit_bytes") != 2 * 1024 * 1024 * 1024
                or model_cgroup.get("pids_limit") != 128
            ):
                raise ValueError("RESOURCE_FAIRNESS_LANE_METRICS_INVALID")
        if phase.get("stress_lane") is None:
            if phase.get("burner") is not None:
                raise ValueError("BASELINE_PHASE_HAS_CPU_BURNER")
            continue
        lane = phase["stress_lane"]
        burner = phase.get("burner", {})
        delta = burner.get("cgroup_delta", {}).get("cpu_stat", {})
        cpuset = burner.get("cpuset_cpus")
        if (
            type(lane) is not int
            or lane not in range(3)
            or burner.get("cpu_quota_cores") != 2
            or burner.get("memory_limit_bytes") != 256 * 1024 * 1024
            or burner.get("pids_limit") != 32
            or burner.get("network_mode") != "none"
            or burner.get("nonroot_readonly_capdrop_no_new_privileges") is not True
            or burner.get("cpu_cores_used", -1) < 0
            or delta.get("usage_usec", -1) < 0
            or cpuset != phase.get("model_cpusets", [None] * 3)[lane]
            or burner.get("cpu_cores_used") != round(delta["usage_usec"] / phase["cgroup_window_elapsed_us"], 6)
            or burner.get("load_detected") is not (burner["cpu_cores_used"] >= 0.50)
            or effective_cpu_quota(burner.get("cgroup_delta", {}).get("cpu_max", "")) != 2
            or normalized_cpu_set(burner.get("cgroup_delta", {}).get("cpuset_cpus_effective", ""))
            != normalized_cpu_set(cpuset or "")
            or burner.get("cgroup_delta", {}).get("memory_limit_bytes") != 256 * 1024 * 1024
            or burner.get("cgroup_delta", {}).get("pids_limit") != 32
        ):
            raise ValueError("CPU_STRESSOR_CONTROL_OR_CGROUP_EVIDENCE_INVALID")
    comparisons = summary.get("lane_comparisons", [])
    baselines = [phase for phase in phases if phase["stress_lane"] is None]
    stress_phases = [phase for phase in phases if phase["stress_lane"] is not None]
    expected_comparisons = []
    for phase in stress_phases:
        lane = phase["stress_lane"]
        values = phase["lanes"]
        baseline = sum(item["lanes"][lane]["output_tokens_per_second"] for item in baselines) / len(baselines)
        loaded = values[lane]["output_tokens_per_second"]
        expected_comparisons.append(
            {
                "stress_lane": lane,
                "baseline_output_tokens_per_second_mean": round(baseline, 6),
                "loaded_output_tokens_per_second": loaded,
                "loaded_to_baseline_ratio": round(loaded / baseline, 6) if baseline else None,
                "relative_change_percent": round((loaded / baseline - 1) * 100, 3) if baseline else None,
                "burner_cpu_cores_used": phase["burner"]["cpu_cores_used"],
                "load_detected": phase["burner"]["load_detected"],
                "observed_other_lane_output_tokens_per_second": {
                    str(other): values[other]["output_tokens_per_second"]
                    for other in range(3) if other != lane
                },
            }
        )
    expected_result = (
        "CPU_LOAD_APPLIED"
        if all(item["load_detected"] for item in expected_comparisons)
        else "INCONCLUSIVE_LOAD_NOT_DETECTED"
    )
    if (
        len(comparisons) != 3
        or [item.get("stress_lane") for item in comparisons] != [0, 1, 2]
        or comparisons != expected_comparisons
        or summary.get("baseline_phases") != 2
        or summary.get("cpu_load_phases") != 3
        or observed.get("result") != expected_result
        or summary.get("minimum_stressor_cpu_cores_for_detected_load") != 0.50
    ):
        raise ValueError("CPU_LOAD_SUMMARY_INVALID")
    return {
        "result": observed["result"],
        "scope": observed["scope"],
        "model_kind": observed["model_kind"],
        "real_inference_performed": observed["real_inference_performed"],
        "real_public_jbb_used": observed["real_public_jbb_used"],
        "phase_count": observed["phase_count"],
        "model_lane_count": observed["model_lane_count"],
        "total_model_calls": observed["total_model_calls"],
        "selected_records_per_split": observed["selected_records_per_split"],
        "selected_record_hashes": [
            {
                "split": item["split"],
                "record_ordinal_sha256": item["record_ordinal_sha256"],
                "prompt_sha256": item["prompt_sha256"],
                "payload_reference_sha256": item["payload_reference_sha256"],
            }
            for item in selected
        ],
        "lane_comparisons": comparisons,
        "phase_lane_resource_counters": [
            {
                "phase": phase["phase"],
                "stress_lane": phase["stress_lane"],
                "inference_window_elapsed_us": phase["inference_window_elapsed_us"],
                "cgroup_window_elapsed_us": phase["cgroup_window_elapsed_us"],
                "lanes": [
                    {
                        "lane": lane["lane"],
                        "output_tokens": lane["output_tokens"],
                        "output_tokens_per_second": lane["output_tokens_per_second"],
                        "median_model_call_duration_us": lane["median_model_call_duration_us"],
                        "model_cgroup_delta": lane["model_cgroup_delta"],
                    }
                    for lane in phase["lanes"]
                ],
                "burner": phase["burner"],
            }
            for phase in phases
        ],
        "limits": {
            "defense_verdicts_observed": False,
            "ram_pid_io_contention_applied": False,
            "full_p011_acceptance": False,
            "host_or_hypervisor_cpu_exclusivity_verified": False,
            "timing_channel_analysis_performed": False,
            "full_n07_acceptance": False,
            "full_arena_acceptance": False,
            "guarantee_tier_achieved": None,
        },
    }


def collect(args: argparse.Namespace) -> int:
    receipt_path = args.output.resolve()
    if receipt_path.parent != EVIDENCE.resolve():
        raise ValueError("RECEIPT_MUST_BE_IN_CANONICAL_MEMORY_EVIDENCE_DIRECTORY")
    outputs_path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    if receipt_path.exists() or outputs_path.exists():
        raise FileExistsError("OUTPUT_PATH_ALREADY_EXISTS_USE_A_NEW_ATTEMPT_PATH")
    offline_python = args.offline_python.resolve()
    if not offline_python.is_file():
        raise FileNotFoundError("OFFLINE_PYTHON_NOT_FOUND")
    required = (args.cell_lock.resolve(), args.model.resolve(), args.corpus.resolve(), args.corpus_receipt.resolve(), args.corpus_keys.resolve())
    if not all(path.exists() for path in required):
        raise FileNotFoundError("PREPARED_LOCAL_MODEL_OR_PUBLIC_CORPUS_INPUT_MISSING")
    private_output = args.private_output.resolve()
    private_preparation = args.private_preparation.resolve()
    artifact_root = (BACKEND / "artifacts").resolve()
    if private_output.exists() or private_preparation.exists():
        raise ValueError("NEW_PRIVATE_RUNTIME_AND_PREPARATION_OUTPUTS_REQUIRED")
    if not private_output.is_relative_to(artifact_root) or not private_preparation.is_relative_to(artifact_root):
        raise ValueError("PRIVATE_OUTPUTS_MUST_REMAIN_UNDER_BACKEND_ARTIFACTS")

    n06_unchanged = historical_receipt_matches(N06_RECEIPT)
    n07a_unchanged = historical_receipt_matches(N07A_RECEIPT)
    if not n06_unchanged or not n07a_unchanged:
        raise ValueError("HISTORICAL_SOURCE_RECEIPT_MISMATCH_BEFORE_COLLECTION")
    before = source_hashes()
    private_observation = private_output / "observation.json"
    prepared_lock = private_preparation / "admission.json"
    receipt: dict[str, Any] = {
        "schema_version": "arena-n07b-resource-fairness.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": SCOPE,
        "result": "COLLECTION_FAILED",
        "collector_state": "IN_PROGRESS",
        "active_command": None,
        "source_sha256": before,
        "source_file_count": len(before),
        "n06_original_sources_unchanged": n06_unchanged,
        "n07a_source_files_unchanged": n07a_unchanged,
        "source_unchanged_during_checks": False,
        "model_kind": "REAL_LOCAL_QWEN_WITH_ADMITTED_PUBLIC_JBB",
        "real_inference_performed": True,
        "real_public_jbb_used": True,
        "cpu_load_control_attempted": True,
        "measurement_result": None,
        "ram_pid_io_contention_applied": False,
        "defense_verdicts_observed": False,
        "timing_channel_analysis_performed": False,
        "full_p011_acceptance": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "wire_contract_changed": False,
        "shared_signing_bytes_changed": False,
        "production_runtime_sources_changed": False,
        "frontend_changed": False,
        "guarantee_tier_achieved": None,
        "private_artifacts": {
            "preparation_output": private_preparation.relative_to(BACKEND).as_posix(),
            "runtime_output": private_output.relative_to(BACKEND).as_posix(),
            "committed": False,
        },
        "private_observation": None,
        "command_results": [],
        "preliminary_runs": [
            preserved_initial_attempt(),
            preserved_stale_report_attempt(),
            preserved_validation_attempt(),
        ],
    }

    def checkpoint() -> None:
        atomic_json(receipt_path, receipt)

    def execute(
        name: str,
        command: list[str],
        cwd: Path,
        *,
        accepted_exit_codes: tuple[int, ...] = (0,),
    ) -> None:
        log = receipt_path.with_name(receipt_path.stem + "-" + name + ".log")
        if log.exists():
            raise FileExistsError("COMMAND_LOG_ALREADY_EXISTS: " + str(log))
        receipt["active_command"] = name
        checkpoint()
        with log.open("xb") as stream:
            proc = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=False)
            stream.flush()
            os.fsync(stream.fileno())
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        item = {
            "name": name,
            "command": command,
            "exit_code": proc.returncode,
            "accepted_exit_codes": list(accepted_exit_codes),
            "log_path": log.relative_to(ROOT).as_posix(),
            "log_sha256": digest(log),
            "summary": next((line.strip() for line in reversed(lines) if line.strip()), ""),
        }
        receipt["command_results"].append(item)
        receipt["active_command"] = None
        checkpoint()
        print(json.dumps({key: item[key] for key in ("name", "exit_code", "summary")}), flush=True)
        if proc.returncode not in accepted_exit_codes:
            raise RuntimeError("REQUIRED_COMMAND_FAILED_" + name.upper().replace("-", "_"))

    try:
        execute(
            "prepare-n05",
            [
                sys.executable,
                "tools/prepare_n05.py",
                "--cell-lock", str(args.cell_lock.resolve()),
                "--output", str(private_preparation),
            ],
            BACKEND,
        )
        execute(
            "resource-fairness-probe",
            [
                sys.executable,
                "tools/run_n07b_resource_fairness_probe.py",
                "--lock", str(prepared_lock),
                "--model", str(args.model.resolve()),
                "--corpus", str(args.corpus.resolve()),
                "--corpus-receipt", str(args.corpus_receipt.resolve()),
                "--corpus-keys", str(args.corpus_keys.resolve()),
                "--output", str(private_output),
            ],
            BACKEND,
            accepted_exit_codes=(0, 2),
        )
        execute("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"], BACKEND)
        execute("pytest-offline", [str(offline_python), "-m", "pytest", "-q", "-W", "error"], BACKEND)
        for name, command in (
            ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
            ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
            ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
            ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
            ("dependencies", [sys.executable, "-m", "pip", "check"]),
        ):
            execute(name, command, BACKEND)
        execute("memory-check-pre-reconciliation", [sys.executable, "tools/check_memory.py"], ROOT)

        prep_log = ROOT / receipt["command_results"][0]["log_path"]
        prep_values = [
            json.loads(line) for line in prep_log.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip().startswith("{")
        ]
        if len(prep_values) != 1 or prep_values[0].get("result") != "PREPARED_NOT_ARENA_READY" or prep_values[0].get("runtime_downloads") is not False:
            raise ValueError("N05_PREPARATION_OBSERVATION_INVALID")
        receipt["preparation"] = {
            "result": prep_values[0]["result"],
            "runtime_downloads": prep_values[0]["runtime_downloads"],
            "model_cpusets": prep_values[0]["model_cpusets"],
            "defense_cpuset": prep_values[0]["defense_cpuset"],
            "observed_mem_available_bytes": prep_values[0]["observed_mem_available_bytes"],
            "admission_sha256": digest(prepared_lock),
        }

        if not private_observation.is_file():
            raise ValueError("RESOURCE_FAIRNESS_PRIVATE_OBSERVATION_MISSING")
        observed = json.loads(private_observation.read_bytes())
        validated = validate_observation(observed)
        probe_log = ROOT / receipt["command_results"][1]["log_path"]
        summaries = [
            json.loads(line)
            for line in probe_log.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip().startswith("{")
        ]
        expected_exit = 0 if observed["result"] == "CPU_LOAD_APPLIED" else 2
        expected_summary = {
            "result": observed["result"],
            "scope": observed["scope"],
            "phase_count": observed["phase_count"],
            "total_model_calls": observed["total_model_calls"],
            "lane_comparisons": observed["summary"]["lane_comparisons"],
            "defense_verdicts_observed": False,
            "ram_pid_io_contention_applied": False,
            "full_p011_acceptance": False,
            "full_n07_acceptance": False,
            "full_arena_acceptance": False,
            "guarantee_tier_achieved": None,
        }
        if (
            len(summaries) != 1
            or summaries[0] != expected_summary
            or receipt["command_results"][1]["exit_code"] != expected_exit
        ):
            raise ValueError("RESOURCE_FAIRNESS_SANITIZED_SUMMARY_MISSING_OR_MISMATCHED")
        receipt["measurement_result"] = observed["result"]
        receipt["cpu_load_applied"] = observed["result"] == "CPU_LOAD_APPLIED"
        receipt["observations"] = validated
        receipt["private_observation"] = {
            "path": private_observation.relative_to(BACKEND).as_posix(),
            "sha256": digest(private_observation),
            "committed": False,
        }

        memory_log = next(
            ROOT / item["log_path"]
            for item in receipt["command_results"]
            if item["name"] == "memory-check-pre-reconciliation"
        )
        memory_result = None
        for line in reversed(memory_log.read_text(encoding="utf-8", errors="replace").splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if value.get("result") == "PASS" and isinstance(value.get("checks"), int):
                memory_result = {
                    key: value[key]
                    for key in ("result", "checks", "revision", "questions", "objectives")
                }
                break
        if memory_result is None:
            raise ValueError("PRE_RECONCILIATION_MEMORY_CHECK_RESULT_MISSING")
        receipt["collector_memory_check"] = memory_result

        receipt["pytest_counts"] = []
        receipt["pytest_skipped_counts"] = []
        receipt["subtest_counts"] = []
        for item in receipt["command_results"]:
            if item["name"] not in {"pytest-primary", "pytest-offline"}:
                continue
            match = re.search(r"(\d+) passed", item["summary"])
            if not match:
                raise ValueError("FULL_PYTEST_COUNT_MISSING: " + item["name"])
            receipt["pytest_counts"].append(int(match.group(1)))
            skipped = re.search(r"(\d+) skipped", item["summary"])
            subtests = re.search(r"(\d+) subtests passed", item["summary"])
            receipt["pytest_skipped_counts"].append(int(skipped.group(1)) if skipped else 0)
            receipt["subtest_counts"].append(int(subtests.group(1)) if subtests else 0)

        after = source_hashes()
        receipt["source_unchanged_during_checks"] = before == after
        if not receipt["source_unchanged_during_checks"]:
            receipt["changed_source_paths"] = sorted(
                path for path in before if before[path] != after.get(path)
            )
            raise ValueError("SOURCE_CHANGED_DURING_CHECKS")
        receipt["source_sha256"] = after
        receipt["source_file_count"] = len(after)
        receipt["collector_state"] = "COMPLETED"
        receipt["result"] = "COLLECTION_VERIFIED"
        receipt["active_command"] = None
        checkpoint()
        outputs = make_outputs_index(receipt_path, receipt)
        print(
            json.dumps(
                {
                    "collection_result": receipt["result"],
                    "measurement_result": receipt["measurement_result"],
                    "scope": receipt["scope"],
                    "receipt": receipt_path.relative_to(ROOT).as_posix(),
                    "receipt_sha256": digest(receipt_path),
                    "outputs_index": outputs.relative_to(ROOT).as_posix(),
                    "outputs_index_sha256": digest(outputs),
                    "source_file_count": receipt["source_file_count"],
                    "pytest_counts": receipt["pytest_counts"],
                    "pytest_skipped_counts": receipt["pytest_skipped_counts"],
                    "model_calls": receipt["observations"]["total_model_calls"],
                    "lane_comparisons": receipt["observations"]["lane_comparisons"],
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 0
    except Exception as exc:
        receipt["collector_state"] = "FAILED"
        receipt["result"] = "COLLECTION_FAILED"
        receipt["failure"] = type(exc).__name__ + ":" + str(exc)[:160]
        receipt["active_command"] = None
        checkpoint()
        if not outputs_path.exists():
            make_outputs_index(receipt_path, receipt)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cell-lock", "model", "corpus", "corpus-receipt", "corpus-keys", "offline-python", "output", "private-output", "private-preparation"):
        parser.add_argument("--" + name, required=True, type=Path)
    try:
        return collect(parser.parse_args())
    except Exception as exc:
        print("N07B resource/fairness collection FAILED: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
