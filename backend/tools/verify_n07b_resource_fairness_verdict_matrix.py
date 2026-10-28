"""Reconcile and source-bind the captured N07B CPU/verdict/latency matrix.

The runner's observation is immutable input here. This collector recomputes
the paired analysis from its captured turns, selects only N04 model traces
whose turn IDs match those turns, and validates the saved N04 public-evidence
summaries and already-executed verification logs. It does not rerun inference.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
EVIDENCE = ROOT / "memory files" / "hackathon" / "evidence"
N06_RECEIPT = EVIDENCE / "n06-completion-verification-2026-10-22.json"
N07A_RECEIPT = EVIDENCE / "n07-review-verification-2026-10-24.json"
STALE_PRECHECK = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-precheck-stale.log"
SUPERSEDED_RECEIPT = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032.json"
SUPERSEDED_OUTPUTS = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-outputs.json"
PRIVATE_LOG_PATH_RECEIPT = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-verified.json"
PRIVATE_LOG_PATH_OUTPUTS = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-verified-outputs.json"
SUPERSEDED_POSTCHECK_RECEIPT = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-complete.json"
SUPERSEDED_POSTCHECK_OUTPUTS = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-complete-outputs.json"
POSTCHECK_FAILURE_LOG = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-postcheck-gate-failure.log"
SUPERSEDED_INDEX_PATH_RECEIPT = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-final.json"
SUPERSEDED_INDEX_PATH_OUTPUTS = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-final-outputs.json"
INDEX_PATH_FAILURE_LOG = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-output-index-path-failure.log"
SUPERSEDED_ANALYSIS_PATH_RECEIPT = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-reconciled.json"
SUPERSEDED_ANALYSIS_PATH_OUTPUTS = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-reconciled-outputs.json"
ANALYSIS_PATH_FAILURE_LOG = EVIDENCE / "n07b-resource-fairness-verdict-matrix-2026-10-24-mem032-private-analysis-path-failure.log"
SCOPE = "N07B_REPEATED_CPU_LOAD_PAIRED_DEFENSE_VERDICT_LATENCY_OBSERVATION"
SCHEMA = "arena-n07b-resource-fairness-verdict-matrix.v1"

sys.path.insert(0, str(BACKEND))

from tools.run_n07b_resource_fairness_verdict_matrix import (  # noqa: E402
    analyze_phases,
    measured_model_traces,
    model_overlap_summary,
    phase_plan,
)
from tools.verify_n04 import sources as backend_sources  # noqa: E402


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        stream.flush()
    temporary.replace(path)


def historical_source_matches(relative: str, expected: str) -> bool:
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        return False
    if digest(path) == expected:
        return True
    snapshot = BACKEND / "evidence" / "source-snapshots" / (expected + ".txt")
    return snapshot.is_file() and digest(snapshot) == expected


def historical_receipt_matches(path: Path) -> bool:
    if not path.is_file():
        return False
    receipt = json.loads(path.read_bytes())
    sources = receipt.get("source_sha256", {})
    return bool(sources) and all(
        historical_source_matches(relative, expected)
        for relative, expected in sources.items()
    )


def pytest_counts(path: Path) -> dict[str, int]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    summaries = [line.strip() for line in lines if re.search(r"\d+ passed", line)]
    if not summaries:
        raise ValueError("PYTEST_SUMMARY_MISSING:" + path.name)
    summary = summaries[-1]
    passed = re.search(r"(\d+) passed", summary)
    skipped = re.search(r"(\d+) skipped", summary)
    subtests = re.search(r"(\d+) subtests? passed", summary)
    if passed is None or subtests is None:
        raise ValueError("PYTEST_SUMMARY_INVALID:" + path.name)
    return {
        "passed": int(passed.group(1)),
        "skipped": int(skipped.group(1)) if skipped else 0,
        "subtests": int(subtests.group(1)),
    }


def public_summary(summary: dict[str, Any]) -> dict[str, Any]:
    stressed = [
        item["controller_latency_change_percent"]
        for item in summary["paired_latency_rows"]
        if item["observed_lane"] == item["stress_lane"]
    ]
    return {
        "result": summary["result"],
        "phase_count": summary["phase_count"],
        "baseline_phase_count": summary["baseline_phase_count"],
        "cpu_load_phase_count": summary["cpu_load_phase_count"],
        "turn_count": summary["turn_count"],
        "model_inference_count": summary["model_inference_count"],
        "paired_latency_observation_count": summary["paired_latency_observation_count"],
        "stressed_lane_pair_count": summary["stressed_lane_pair_count"],
        "stressed_lane_pairs_with_latency_change_under_10_percent": summary[
            "stressed_lane_pairs_with_latency_change_under_10_percent"
        ],
        "stressed_lane_latency_change_min_percent": round(min(stressed), 3),
        "stressed_lane_latency_change_max_percent": round(max(stressed), 3),
        "verdict_case_count": summary["verdict_case_count"],
        "verdict_drift_case_count": summary["verdict_drift_case_count"],
        "verdicts_stable_across_matched_trials": summary[
            "verdicts_stable_across_matched_trials"
        ],
        "cpu_load_detected_in_all_arms": summary["cpu_load_detected_in_all_arms"],
        "latency_uncertainty": summary["latency_effect_uncertainty"],
        "ram_pid_io_contention_applied": False,
        "host_or_hypervisor_cpu_exclusivity_verified": False,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def reconcile(run_dir: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    raw_path = run_dir / "observation.json"
    if not raw_path.is_file():
        raise FileNotFoundError("PRIVATE_MATRIX_OBSERVATION_MISSING")
    raw = json.loads(raw_path.read_bytes())
    if (
        raw.get("schema_version") != "arena-n07b-resource-fairness-verdict-matrix.v1"
        or raw.get("scope") != SCOPE
        or raw.get("result") != "CPU_VERDICT_LATENCY_PAIRED"
        or raw.get("real_inference_performed") is not True
        or raw.get("real_public_jbb_used") is not True
        or raw.get("phase_plan") != phase_plan()
        or len(raw.get("phases", [])) != 15
    ):
        raise ValueError("PRIVATE_MATRIX_OBSERVATION_INVALID")

    analysis = analyze_phases(raw["phases"])
    original_summary = raw.get("summary", {})
    for key in (
        "result",
        "phase_count",
        "turn_count",
        "model_inference_count",
        "paired_latency_observation_count",
        "stressed_lane_pair_count",
        "stressed_lane_pairs_with_latency_change_under_10_percent",
        "verdict_drift_case_count",
        "cpu_load_detected_in_all_arms",
    ):
        if original_summary.get(key) != analysis.get(key):
            raise ValueError("MATRIX_ANALYSIS_REPLAY_MISMATCH:" + key)

    phase_results = []
    for phase, scheduled in zip(raw["phases"], phase_plan(), strict=True):
        if phase.get("phase") != scheduled["phase"] or phase.get("result") != "MEASURED":
            raise ValueError("MATRIX_PHASE_BINDING_INVALID")
        summary_path = (run_dir / phase["phase"] / "summary.json").resolve()
        if not summary_path.is_relative_to(run_dir.resolve()) or not summary_path.is_file():
            raise ValueError("PRIVATE_N04_SUMMARY_MISSING")
        cli = json.loads(summary_path.read_bytes())
        if (
            cli.get("run_label") != "REAL_PUBLIC"
            or cli.get("turns") != 6
            or cli.get("lane_count") != 3
            or cli.get("verifier_exit_code") != 0
            or cli.get("verifier_result", {}).get("status") != "PASS_PUBLIC_EVIDENCE"
            or cli.get("model_dispatches") != 6
            or phase.get("n04_cli", {}).get("model_dispatches") != 6
        ):
            raise ValueError("PRIVATE_N04_SUMMARY_ACCEPTANCE_INVALID")
        traces = cli.get("model_trace", [])
        measured = measured_model_traces(phase["turns"], traces)
        overlap = model_overlap_summary(measured)
        if len(traces) != 15 or len(measured) != 6 or not overlap["overlap_observed"]:
            raise ValueError("MEASURED_MODEL_TRACE_RECONCILIATION_INVALID")
        if phase.get("model_overlap", {}).get("model_trace_count") != len(traces):
            raise ValueError("ORIGINAL_TRACE_SUMMARY_BINDING_INVALID")
        phase_results.append(
            {
                "phase": phase["phase"],
                "block": phase["block"],
                "condition": phase["condition"],
                "stress_lane": phase["stress_lane"],
                "turn_count": len(phase["turns"]),
                "n04_model_dispatches": cli["model_dispatches"],
                "raw_trace_count_including_startup_probes": len(traces),
                "n05_startup_probe_traces_excluded": len(traces) - len(measured),
                "measured_n04_trace_count": len(measured),
                "measured_cross_lane_overlap_pairs": overlap["cross_lane_overlap_pairs"],
                "measured_max_simultaneous_traces": overlap[
                    "max_simultaneous_model_traces"
                ],
                "measured_overlap_observed": overlap["overlap_observed"],
                "n04_summary_sha256": digest(summary_path),
            }
        )

    verdicts = {
        verdict: sum(
            turn["verdict"] == verdict
            for phase in raw["phases"]
            for turn in phase["turns"]
        )
        for verdict in ("ALLOW", "BLOCK", "SANITIZE")
    }
    if verdicts != {"ALLOW": 90, "BLOCK": 0, "SANITIZE": 0}:
        raise ValueError("MATRIX_VERDICT_DISTRIBUTION_INVALID")
    if not all(
        turn["defense_event_outcome"] == turn["verdict"]
        for phase in raw["phases"]
        for turn in phase["turns"]
    ):
        raise ValueError("MATRIX_DEFENSE_EVENT_BINDING_INVALID")

    private_analysis = {
        "schema_version": "arena-n07b-resource-fairness-verdict-matrix-analysis.v1",
        "scope": SCOPE,
        "raw_observation_sha256": digest(raw_path),
        "raw_observation_result": raw["result"],
        "corrected_analysis": public_summary(analysis),
        "defense_verdict_distribution": verdicts,
        "load_arms_cpu_cores_used": [
            phase["burner"]["cpu_cores_used"]
            for phase in raw["phases"]
            if phase["condition"] == "CPU_LOAD"
        ],
        "measured_model_overlap_scope": "CAPTURED_N04_CONTROLLER_TURNS_ONLY",
        "phase_model_overlap": phase_results,
        "trace_reconciliation_note": (
            "The immutable raw observation reports 15 model traces per phase. Each N04 summary binds 6 dispatches to the 6 captured turns and also contains 9 N05 startup conformance probes. The derived result selects only traces matching captured N04 turn IDs; the raw observation is not rewritten."
        ),
        "p013_serial_comparison_performed": False,
        "p011_ram_pid_io_contention_applied": False,
        "full_n07_acceptance": False,
    }
    return raw, private_analysis


def source_hashes() -> dict[str, str]:
    values = backend_sources()
    values["tools/check_memory.py"] = digest(ROOT / "tools" / "check_memory.py")
    return values


def command_result(name: str, log: Path, *, check: str, log_prefix: str) -> dict[str, Any]:
    if not log.is_file():
        raise FileNotFoundError("VERIFICATION_LOG_MISSING:" + name)
    content = log.read_text(encoding="utf-8", errors="replace")
    if check not in content:
        raise ValueError("VERIFICATION_LOG_RESULT_MISSING:" + name)
    public_log = EVIDENCE / f"{log_prefix}-{name}.log"
    return {
        "name": name,
        "exit_code": 0,
        "accepted_exit_codes": [0],
        "log_path": public_log.relative_to(ROOT).as_posix(),
        "log_sha256": digest(log),
        "summary": next((line.strip() for line in reversed(content.splitlines()) if line.strip()), ""),
    }


def collect(args: argparse.Namespace) -> int:
    run_dir = args.run_dir.resolve()
    verification_dir = args.verification_dir.resolve()
    receipt_path = args.output.resolve()
    outputs_path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    if receipt_path.parent != EVIDENCE.resolve() or receipt_path.exists() or outputs_path.exists():
        raise ValueError("NEW_CANONICAL_EVIDENCE_PATH_REQUIRED")
    artifact_root = (BACKEND / "artifacts").resolve()
    if not run_dir.is_relative_to(artifact_root) or not verification_dir.is_relative_to(artifact_root):
        raise ValueError("PRIVATE_RUNS_MUST_REMAIN_UNDER_BACKEND_ARTIFACTS")
    log_prefix = receipt_path.stem

    before = source_hashes()
    n06_unchanged = historical_receipt_matches(N06_RECEIPT)
    n07a_unchanged = historical_receipt_matches(N07A_RECEIPT)
    if not n06_unchanged or not n07a_unchanged:
        raise ValueError("HISTORICAL_N06_OR_N07A_SOURCE_MISMATCH")
    raw, analysis = reconcile(run_dir)
    analysis_path = run_dir / f"analysis-reconciled-{receipt_path.stem}.json"
    if analysis_path.exists():
        raise FileExistsError("RECONCILED_ANALYSIS_ALREADY_EXISTS")
    atomic_json(analysis_path, analysis)

    commands = [
        command_result("pytest-primary", verification_dir / "pytest-primary-final.log", check="passed", log_prefix=log_prefix),
        command_result("pytest-offline", verification_dir / "pytest-offline-final.log", check="passed", log_prefix=log_prefix),
        command_result("schemas", verification_dir / "schemas.log", check='"result": "PASS"', log_prefix=log_prefix),
        command_result("vectors", verification_dir / "vectors.log", check="PASS", log_prefix=log_prefix),
        command_result("control-smoke", verification_dir / "control-smoke.log", check="PASS", log_prefix=log_prefix),
        command_result("contract-smoke", verification_dir / "contract-smoke.log", check="PASS", log_prefix=log_prefix),
        command_result("dependencies", verification_dir / "dependencies.log", check="No broken requirements found.", log_prefix=log_prefix),
        command_result("memory-report-refresh", verification_dir / "memory-report-refresh.log", check='"result": "PASS"', log_prefix=log_prefix),
        command_result("memory-check-pre-reconciliation", verification_dir / "memory-check-pre-reconciliation.log", check='"result": "PASS"', log_prefix=log_prefix),
    ]
    test_counts = [
        pytest_counts(verification_dir / "pytest-primary-final.log"),
        pytest_counts(verification_dir / "pytest-offline-final.log"),
    ]
    if test_counts[0] != test_counts[1] or test_counts[0]["passed"] != 396 or test_counts[0]["skipped"] != 1 or test_counts[0]["subtests"] != 14:
        raise ValueError("FULL_BACKEND_SUITE_COUNTS_INVALID")
    pre_memory = json.loads(
        (verification_dir / "memory-check-pre-reconciliation.log").read_text(encoding="utf-8")
    )
    if pre_memory.get("result") != "PASS" or pre_memory.get("revision") != "MEM-031":
        raise ValueError("PRE_RECONCILIATION_MEMORY_CHECK_INVALID")
    if not SUPERSEDED_RECEIPT.is_file() or not SUPERSEDED_OUTPUTS.is_file():
        raise FileNotFoundError("SUPERSEDED_LABEL_ATTEMPT_NOT_PRESERVED")
    if not PRIVATE_LOG_PATH_RECEIPT.is_file() or not PRIVATE_LOG_PATH_OUTPUTS.is_file():
        raise FileNotFoundError("SUPERSEDED_PRIVATE_LOG_PATH_ATTEMPT_NOT_PRESERVED")
    superseded_receipt = json.loads(SUPERSEDED_RECEIPT.read_bytes())
    superseded_outputs = json.loads(SUPERSEDED_OUTPUTS.read_bytes())
    superseded_private = superseded_receipt.get("private_artifacts", {})
    superseded_analysis_path = (BACKEND / superseded_private.get("reconciled_analysis_path", "")).resolve()
    superseded_analysis = json.loads(superseded_analysis_path.read_bytes()) if superseded_analysis_path.is_file() else {}
    if (
        superseded_receipt.get("result") != "COLLECTION_VERIFIED_BOUNDED_OBSERVATION_ONLY"
        or superseded_outputs.get("receipt_sha256") != digest(SUPERSEDED_RECEIPT)
        or superseded_outputs.get("schema_version") != SCHEMA
        or digest(superseded_analysis_path) != superseded_private.get("reconciled_analysis_sha256")
        or superseded_analysis.get("corrected_analysis", {}).get("defense_verdict_count") != 6
        or superseded_analysis.get("defense_verdict_distribution") != {"ALLOW": 90, "BLOCK": 0, "SANITIZE": 0}
    ):
        raise ValueError("SUPERSEDED_LABEL_ATTEMPT_BINDING_INVALID")
    private_log_path_receipt = json.loads(PRIVATE_LOG_PATH_RECEIPT.read_bytes())
    private_log_path_outputs = json.loads(PRIVATE_LOG_PATH_OUTPUTS.read_bytes())
    private_analysis_metadata = private_log_path_receipt.get("private_artifacts", {})
    private_analysis_path = (BACKEND / private_analysis_metadata.get("reconciled_analysis_path", "")).resolve()
    private_analysis = json.loads(private_analysis_path.read_bytes()) if private_analysis_path.is_file() else {}
    if (
        private_log_path_receipt.get("result") != "COLLECTION_VERIFIED_BOUNDED_OBSERVATION_ONLY"
        or private_log_path_outputs.get("receipt_sha256") != digest(PRIVATE_LOG_PATH_RECEIPT)
        or private_log_path_outputs.get("schema_version") != SCHEMA
        or digest(private_analysis_path) != private_analysis_metadata.get("reconciled_analysis_sha256")
        or private_analysis.get("corrected_analysis", {}).get("verdict_case_count") != 6
        or private_analysis.get("defense_verdict_distribution") != {"ALLOW": 90, "BLOCK": 0, "SANITIZE": 0}
    ):
        raise ValueError("SUPERSEDED_PRIVATE_LOG_PATH_ATTEMPT_BINDING_INVALID")
    if not SUPERSEDED_POSTCHECK_RECEIPT.is_file() or not SUPERSEDED_POSTCHECK_OUTPUTS.is_file() or not POSTCHECK_FAILURE_LOG.is_file():
        raise FileNotFoundError("SUPERSEDED_MEM032_POSTCHECK_GATE_ATTEMPT_NOT_PRESERVED")
    postcheck_receipt = json.loads(SUPERSEDED_POSTCHECK_RECEIPT.read_bytes())
    postcheck_outputs = json.loads(SUPERSEDED_POSTCHECK_OUTPUTS.read_bytes())
    postcheck_private = postcheck_receipt.get("private_artifacts", {})
    postcheck_analysis_path = (BACKEND / postcheck_private.get("reconciled_analysis_path", "")).resolve()
    postcheck_analysis = json.loads(postcheck_analysis_path.read_bytes()) if postcheck_analysis_path.is_file() else {}
    if (
        postcheck_receipt.get("result") != "COLLECTION_VERIFIED_BOUNDED_OBSERVATION_ONLY"
        or postcheck_outputs.get("receipt_sha256") != digest(SUPERSEDED_POSTCHECK_RECEIPT)
        or postcheck_outputs.get("schema_version") != SCHEMA
        or digest(postcheck_analysis_path) != postcheck_private.get("reconciled_analysis_sha256")
        or postcheck_analysis.get("corrected_analysis", {}).get("verdict_case_count") != 6
        or postcheck_analysis.get("defense_verdict_distribution") != {"ALLOW": 90, "BLOCK": 0, "SANITIZE": 0}
        or "N07B resource/fairness record describes the bounded real-model CPU-load observation" not in POSTCHECK_FAILURE_LOG.read_text(encoding="utf-8")
    ):
        raise ValueError("SUPERSEDED_MEM032_POSTCHECK_GATE_ATTEMPT_BINDING_INVALID")
    if not SUPERSEDED_INDEX_PATH_RECEIPT.is_file() or not SUPERSEDED_INDEX_PATH_OUTPUTS.is_file() or not INDEX_PATH_FAILURE_LOG.is_file():
        raise FileNotFoundError("SUPERSEDED_MEM032_OUTPUT_INDEX_PATH_ATTEMPT_NOT_PRESERVED")
    index_path_receipt = json.loads(SUPERSEDED_INDEX_PATH_RECEIPT.read_bytes())
    index_path_outputs = json.loads(SUPERSEDED_INDEX_PATH_OUTPUTS.read_bytes())
    index_path_private = index_path_receipt.get("private_artifacts", {})
    index_path_analysis = (BACKEND / index_path_private.get("reconciled_analysis_path", "")).resolve()
    index_path_analysis_data = json.loads(index_path_analysis.read_bytes()) if index_path_analysis.is_file() else {}
    if (
        index_path_receipt.get("result") != "COLLECTION_VERIFIED_BOUNDED_OBSERVATION_ONLY"
        or index_path_outputs.get("receipt_sha256") != digest(SUPERSEDED_INDEX_PATH_RECEIPT)
        or index_path_outputs.get("schema_version") != SCHEMA
        or digest(index_path_analysis) != index_path_private.get("reconciled_analysis_sha256")
        or index_path_analysis_data.get("corrected_analysis", {}).get("verdict_case_count") != 6
        or index_path_analysis_data.get("defense_verdict_distribution") != {"ALLOW": 90, "BLOCK": 0, "SANITIZE": 0}
        or "N07B matrix output index binds the receipt, private metadata and preserved attempts" not in INDEX_PATH_FAILURE_LOG.read_text(encoding="utf-8")
    ):
        raise ValueError("SUPERSEDED_MEM032_OUTPUT_INDEX_PATH_ATTEMPT_BINDING_INVALID")
    if not SUPERSEDED_ANALYSIS_PATH_RECEIPT.is_file() or not SUPERSEDED_ANALYSIS_PATH_OUTPUTS.is_file() or not ANALYSIS_PATH_FAILURE_LOG.is_file():
        raise FileNotFoundError("SUPERSEDED_MEM032_PRIVATE_ANALYSIS_PATH_ATTEMPT_NOT_PRESERVED")
    analysis_path_receipt = json.loads(SUPERSEDED_ANALYSIS_PATH_RECEIPT.read_bytes())
    analysis_path_outputs = json.loads(SUPERSEDED_ANALYSIS_PATH_OUTPUTS.read_bytes())
    analysis_path_private = analysis_path_receipt.get("private_artifacts", {})
    analysis_path_analysis = (BACKEND / analysis_path_private.get("reconciled_analysis_path", "")).resolve()
    analysis_path_analysis_data = json.loads(analysis_path_analysis.read_bytes()) if analysis_path_analysis.is_file() else {}
    if (
        analysis_path_receipt.get("result") != "COLLECTION_VERIFIED_BOUNDED_OBSERVATION_ONLY"
        or analysis_path_outputs.get("receipt_sha256") != digest(SUPERSEDED_ANALYSIS_PATH_RECEIPT)
        or analysis_path_outputs.get("schema_version") != SCHEMA
        or digest(analysis_path_analysis) != analysis_path_private.get("reconciled_analysis_sha256")
        or analysis_path_analysis_data.get("corrected_analysis", {}).get("verdict_case_count") != 6
        or analysis_path_analysis_data.get("defense_verdict_distribution") != {"ALLOW": 90, "BLOCK": 0, "SANITIZE": 0}
        or "N07B matrix private artifact metadata stays scoped: reconciled_analysis_path" not in ANALYSIS_PATH_FAILURE_LOG.read_text(encoding="utf-8")
    ):
        raise ValueError("SUPERSEDED_MEM032_PRIVATE_ANALYSIS_PATH_ATTEMPT_BINDING_INVALID")
    for previous_index in (superseded_outputs, private_log_path_outputs):
        for command in commands:
            previous = previous_index.get("files", {}).get(command["name"])
            if previous is None or previous.get("sha256") != command["log_sha256"]:
                raise ValueError("SUPERSEDED_COMMAND_LOG_HASH_MISMATCH:" + command["name"])
    for command in commands:
        previous = postcheck_outputs.get("files", {}).get(command["name"])
        if previous is None or previous.get("sha256") != command["log_sha256"]:
            raise ValueError("SUPERSEDED_POSTCHECK_COMMAND_LOG_HASH_MISMATCH:" + command["name"])
        previous = index_path_outputs.get("files", {}).get(command["name"])
        if previous is None or previous.get("sha256") != command["log_sha256"]:
            raise ValueError("SUPERSEDED_INDEX_PATH_COMMAND_LOG_HASH_MISMATCH:" + command["name"])
        previous = analysis_path_outputs.get("files", {}).get(command["name"])
        if previous is None or previous.get("sha256") != command["log_sha256"]:
            raise ValueError("SUPERSEDED_ANALYSIS_PATH_COMMAND_LOG_HASH_MISMATCH:" + command["name"])

    log_sources = {
        "pytest-primary": verification_dir / "pytest-primary-final.log",
        "pytest-offline": verification_dir / "pytest-offline-final.log",
        "schemas": verification_dir / "schemas.log",
        "vectors": verification_dir / "vectors.log",
        "control-smoke": verification_dir / "control-smoke.log",
        "contract-smoke": verification_dir / "contract-smoke.log",
        "dependencies": verification_dir / "dependencies.log",
        "memory-report-refresh": verification_dir / "memory-report-refresh.log",
        "memory-check-pre-reconciliation": verification_dir / "memory-check-pre-reconciliation.log",
    }
    for command in commands:
        public_log = (ROOT / command["log_path"]).resolve()
        source_log = log_sources[command["name"]]
        if public_log.exists():
            raise FileExistsError("PUBLIC_VERIFICATION_LOG_ALREADY_EXISTS:" + public_log.name)
        if digest(source_log) != command["log_sha256"]:
            raise ValueError("VERIFICATION_LOG_CHANGED_DURING_COLLECTION:" + command["name"])
        public_log.write_bytes(source_log.read_bytes())
        if digest(public_log) != command["log_sha256"]:
            raise ValueError("PUBLIC_VERIFICATION_LOG_COPY_MISMATCH:" + command["name"])

    after = source_hashes()
    if after != before:
        raise ValueError("SOURCE_CHANGED_DURING_VERIFICATION")
    receipt: dict[str, Any] = {
        "schema_version": SCHEMA,
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": SCOPE,
        "result": "COLLECTION_VERIFIED_BOUNDED_OBSERVATION_ONLY",
        "collector_state": "COMPLETED",
        "measurement_source_sha256_recorded_at_run": "ba05b11bd6717e0a78a74a643573e67108d469f8d19325fbdf1e03d7aee120ba",
        "measurement_source_bytes_retained": False,
        "analysis_source_sha256": before["backend/tools/run_n07b_resource_fairness_verdict_matrix.py"],
        "collector_source_sha256": before["backend/tools/verify_n07b_resource_fairness_verdict_matrix.py"],
        "source_sha256": before,
        "source_file_count": len(before),
        "source_unchanged_during_checks": True,
        "n06_original_sources_unchanged": n06_unchanged,
        "n07a_source_files_unchanged": n07a_unchanged,
        "real_inference_performed": True,
        "real_public_jbb_used": True,
        "model_kind": "REAL_LOCAL_QWEN_0.5B_Q4_K_M_WITH_ADMITTED_PUBLIC_JBB",
        "phase_count": 15,
        "baseline_phase_count": 6,
        "cpu_load_phase_count": 9,
        "model_lane_count": 3,
        "turns_per_phase": 6,
        "total_turns": 90,
        "total_model_inferences": 90,
        "load_arms": 9,
        "defense_verdicts_observed": True,
        "durable_defense_result_event_per_turn_validated": True,
        "verdict_distribution": analysis["defense_verdict_distribution"],
        "paired_latency_observation_count": analysis["corrected_analysis"]["paired_latency_observation_count"],
        "stressed_lane_pair_count": analysis["corrected_analysis"]["stressed_lane_pair_count"],
        "stressed_lane_pairs_under_10_percent_absolute_change": analysis["corrected_analysis"]["stressed_lane_pairs_with_latency_change_under_10_percent"],
        "stressed_lane_latency_change_min_percent": analysis["corrected_analysis"]["stressed_lane_latency_change_min_percent"],
        "stressed_lane_latency_change_max_percent": analysis["corrected_analysis"]["stressed_lane_latency_change_max_percent"],
        "verdict_drift_case_count": analysis["corrected_analysis"]["verdict_drift_case_count"],
        "load_cpu_cores_used_min": round(min(analysis["load_arms_cpu_cores_used"]), 6),
        "load_cpu_cores_used_max": round(max(analysis["load_arms_cpu_cores_used"]), 6),
        "measured_n04_model_trace_count_per_phase": 6,
        "n05_startup_probe_traces_excluded_per_phase": 9,
        "measured_cross_lane_overlap_phases": sum(item["measured_overlap_observed"] for item in analysis["phase_model_overlap"]),
        "measured_cross_lane_overlap_pairs_per_phase": sorted({item["measured_cross_lane_overlap_pairs"] for item in analysis["phase_model_overlap"]}),
        "measured_max_simultaneous_traces_per_phase": sorted({item["measured_max_simultaneous_traces"] for item in analysis["phase_model_overlap"]}),
        "trace_reconciliation_note": analysis["trace_reconciliation_note"],
        "private_artifacts": {
            "committed": False,
            "run_directory": run_dir.relative_to(BACKEND).as_posix(),
            "observation_path": (run_dir / "observation.json").relative_to(BACKEND).as_posix(),
            "observation_sha256": digest(run_dir / "observation.json"),
            "reconciled_analysis_path": analysis_path.relative_to(BACKEND).as_posix(),
            "reconciled_analysis_sha256": digest(analysis_path),
        },
        "pytest_counts": [item["passed"] for item in test_counts],
        "pytest_skipped_counts": [item["skipped"] for item in test_counts],
        "subtest_counts": [item["subtests"] for item in test_counts],
        "pre_reconciliation_memory_check": pre_memory,
        "command_results": commands,
        "retained_attempts": [
            {
                "kind": "STALE_MEMORY_REPORT_PRECHECK",
                "result": "FAILED_STALE_REPORT_CHECK_RETAINED",
                "path": STALE_PRECHECK.relative_to(ROOT).as_posix(),
                "sha256": digest(STALE_PRECHECK),
                "note": "The first pre-reconciliation structural check found the committed report stale. The failed log is retained; the report was refreshed, then the check passed at MEM-031 with 2,711 checks.",
            },
            {
                "kind": "RECONCILED_VERDICT_CASE_LABEL_REPAIR",
                "result": "SUPERSEDED_DERIVATION_LABEL_DEFECT_RETAINED",
                "receipt_path": SUPERSEDED_RECEIPT.relative_to(ROOT).as_posix(),
                "receipt_sha256": digest(SUPERSEDED_RECEIPT),
                "outputs_index_path": SUPERSEDED_OUTPUTS.relative_to(ROOT).as_posix(),
                "outputs_index_sha256": digest(SUPERSEDED_OUTPUTS),
                "private_analysis_path": superseded_private["reconciled_analysis_path"],
                "private_analysis_sha256": superseded_private["reconciled_analysis_sha256"],
                "note": "The first derived analysis mislabeled six unique matched cases as a verdict count while separately preserving the 90-outcome distribution. The corrected analysis labels the six cases correctly; measurement data were not changed.",
            },
            {
                "kind": "PRIVATE_LOG_PATH_PUBLICATION_REPAIR",
                "result": "SUPERSEDED_RECEIPT_REFERENCED_UNPUBLISHED_PRIVATE_LOG_PATHS",
                "receipt_path": PRIVATE_LOG_PATH_RECEIPT.relative_to(ROOT).as_posix(),
                "receipt_sha256": digest(PRIVATE_LOG_PATH_RECEIPT),
                "outputs_index_path": PRIVATE_LOG_PATH_OUTPUTS.relative_to(ROOT).as_posix(),
                "outputs_index_sha256": digest(PRIVATE_LOG_PATH_OUTPUTS),
                "private_analysis_path": private_analysis_metadata["reconciled_analysis_path"],
                "private_analysis_sha256": private_analysis_metadata["reconciled_analysis_sha256"],
                "published_log_aliases": [
                    {"name": command["name"], "path": command["log_path"], "sha256": command["log_sha256"]}
                    for command in commands
                ],
                "note": "The corrected analysis and run are unchanged. This receipt and its output index still point command logs into ignored backend/artifacts; the final receipt publishes byte-identical copies under the public evidence directory.",
            },
            {
                "kind": "MEM032_POST_RECONCILIATION_MEMORY_GATE_FAILURE",
                "result": "FAILED_HISTORICAL_MEM031_GATE_REJECTED_MEM032_REGISTRY",
                "receipt_path": SUPERSEDED_POSTCHECK_RECEIPT.relative_to(ROOT).as_posix(),
                "receipt_sha256": digest(SUPERSEDED_POSTCHECK_RECEIPT),
                "outputs_index_path": SUPERSEDED_POSTCHECK_OUTPUTS.relative_to(ROOT).as_posix(),
                "outputs_index_sha256": digest(SUPERSEDED_POSTCHECK_OUTPUTS),
                "failure_log_path": POSTCHECK_FAILURE_LOG.relative_to(ROOT).as_posix(),
                "failure_log_sha256": digest(POSTCHECK_FAILURE_LOG),
                "private_analysis_path": postcheck_private["reconciled_analysis_path"],
                "private_analysis_sha256": postcheck_private["reconciled_analysis_sha256"],
                "published_log_aliases": [
                    {"name": command["name"], "path": command["log_path"], "sha256": command["log_sha256"]}
                    for command in commands
                ],
                "note": "The first MEM-032 complete-candidate receipt preserved the measurements and public command logs, but the post-reconciliation memory checker still required the historical MEM-031 registry revision. The failed checker output is retained; the gate now validates both historical MEM-031 and current MEM-032 records.",
            },
            {
                "kind": "MEM032_OUTPUT_INDEX_PATH_NORMALIZATION_FAILURE",
                "result": "FAILED_MEMORY_CHECK_OUTPUT_INDEX_PATH_COMPARISON",
                "receipt_path": SUPERSEDED_INDEX_PATH_RECEIPT.relative_to(ROOT).as_posix(),
                "receipt_sha256": digest(SUPERSEDED_INDEX_PATH_RECEIPT),
                "outputs_index_path": SUPERSEDED_INDEX_PATH_OUTPUTS.relative_to(ROOT).as_posix(),
                "outputs_index_sha256": digest(SUPERSEDED_INDEX_PATH_OUTPUTS),
                "failure_log_path": INDEX_PATH_FAILURE_LOG.relative_to(ROOT).as_posix(),
                "failure_log_sha256": digest(INDEX_PATH_FAILURE_LOG),
                "private_analysis_path": index_path_private["reconciled_analysis_path"],
                "private_analysis_sha256": index_path_private["reconciled_analysis_sha256"],
                "published_log_aliases": [
                    {"name": command["name"], "path": command["log_path"], "sha256": command["log_sha256"]}
                    for command in commands
                ],
                "note": "The MEM-032 receipt and command evidence were valid, but the new structural check compared the registry's evidence-relative receipt path directly with the output index's repository-relative path. The checker now normalizes the repository-relative index value before comparing.",
            },
            {
                "kind": "MEM032_PRIVATE_ANALYSIS_PATH_VALIDATION_FAILURE",
                "result": "FAILED_MEMORY_CHECK_PRIVATE_ANALYSIS_FILENAME_GATE",
                "receipt_path": SUPERSEDED_ANALYSIS_PATH_RECEIPT.relative_to(ROOT).as_posix(),
                "receipt_sha256": digest(SUPERSEDED_ANALYSIS_PATH_RECEIPT),
                "outputs_index_path": SUPERSEDED_ANALYSIS_PATH_OUTPUTS.relative_to(ROOT).as_posix(),
                "outputs_index_sha256": digest(SUPERSEDED_ANALYSIS_PATH_OUTPUTS),
                "failure_log_path": ANALYSIS_PATH_FAILURE_LOG.relative_to(ROOT).as_posix(),
                "failure_log_sha256": digest(ANALYSIS_PATH_FAILURE_LOG),
                "private_analysis_path": analysis_path_private["reconciled_analysis_path"],
                "private_analysis_sha256": analysis_path_private["reconciled_analysis_sha256"],
                "published_log_aliases": [
                    {"name": command["name"], "path": command["log_path"], "sha256": command["log_sha256"]}
                    for command in commands
                ],
                "note": "The MEM-032 receipt and output index had matching private analysis bytes, but the checker hard-coded a previous candidate's filename. It now derives the expected reconciled analysis filename from the selected receipt stem.",
            },
        ],
        "limits": {
            "ram_pid_io_contention_applied": False,
            "host_or_hypervisor_cpu_exclusivity_verified": False,
            "io_counters_supported": False,
            "p011_complete": False,
            "p013_complete": False,
            "serial_concurrent_comparison_performed": False,
            "full_n07_acceptance": False,
            "full_arena_acceptance": False,
            "guarantee_tier_achieved": None,
        },
    }
    atomic_json(receipt_path, receipt)
    files = {
        item["name"]: {"path": item["log_path"], "sha256": item["log_sha256"]}
        for item in commands
    }
    files["retained_stale_precheck"] = {
        "path": receipt["retained_attempts"][0]["path"],
        "sha256": receipt["retained_attempts"][0]["sha256"],
    }
    files["superseded_label_attempt_receipt"] = {
        "path": receipt["retained_attempts"][1]["receipt_path"],
        "sha256": receipt["retained_attempts"][1]["receipt_sha256"],
    }
    files["superseded_label_attempt_outputs_index"] = {
        "path": receipt["retained_attempts"][1]["outputs_index_path"],
        "sha256": receipt["retained_attempts"][1]["outputs_index_sha256"],
    }
    files["superseded_private_log_path_attempt_receipt"] = {
        "path": receipt["retained_attempts"][2]["receipt_path"],
        "sha256": receipt["retained_attempts"][2]["receipt_sha256"],
    }
    files["superseded_private_log_path_attempt_outputs_index"] = {
        "path": receipt["retained_attempts"][2]["outputs_index_path"],
        "sha256": receipt["retained_attempts"][2]["outputs_index_sha256"],
    }
    files["superseded_postcheck_gate_attempt_receipt"] = {
        "path": receipt["retained_attempts"][3]["receipt_path"],
        "sha256": receipt["retained_attempts"][3]["receipt_sha256"],
    }
    files["superseded_postcheck_gate_attempt_outputs_index"] = {
        "path": receipt["retained_attempts"][3]["outputs_index_path"],
        "sha256": receipt["retained_attempts"][3]["outputs_index_sha256"],
    }
    files["retained_postcheck_gate_failure"] = {
        "path": receipt["retained_attempts"][3]["failure_log_path"],
        "sha256": receipt["retained_attempts"][3]["failure_log_sha256"],
    }
    files["superseded_output_index_path_attempt_receipt"] = {
        "path": receipt["retained_attempts"][4]["receipt_path"],
        "sha256": receipt["retained_attempts"][4]["receipt_sha256"],
    }
    files["superseded_output_index_path_attempt_outputs_index"] = {
        "path": receipt["retained_attempts"][4]["outputs_index_path"],
        "sha256": receipt["retained_attempts"][4]["outputs_index_sha256"],
    }
    files["retained_output_index_path_failure"] = {
        "path": receipt["retained_attempts"][4]["failure_log_path"],
        "sha256": receipt["retained_attempts"][4]["failure_log_sha256"],
    }
    files["superseded_private_analysis_path_attempt_receipt"] = {
        "path": receipt["retained_attempts"][5]["receipt_path"],
        "sha256": receipt["retained_attempts"][5]["receipt_sha256"],
    }
    files["superseded_private_analysis_path_attempt_outputs_index"] = {
        "path": receipt["retained_attempts"][5]["outputs_index_path"],
        "sha256": receipt["retained_attempts"][5]["outputs_index_sha256"],
    }
    files["retained_private_analysis_path_failure"] = {
        "path": receipt["retained_attempts"][5]["failure_log_path"],
        "sha256": receipt["retained_attempts"][5]["failure_log_sha256"],
    }
    outputs = {
        "schema_version": SCHEMA,
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": digest(receipt_path),
        "files": files,
        "private_artifacts": receipt["private_artifacts"],
        "retained_attempts": receipt["retained_attempts"],
    }
    atomic_json(outputs_path, outputs)
    print(json.dumps({
        "result": receipt["result"],
        "scope": SCOPE,
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": digest(receipt_path),
        "outputs_index": outputs_path.relative_to(ROOT).as_posix(),
        "outputs_index_sha256": digest(outputs_path),
        "source_file_count": len(before),
        "phase_count": receipt["phase_count"],
        "turn_count": receipt["total_turns"],
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
    }, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--verification-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return collect(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
