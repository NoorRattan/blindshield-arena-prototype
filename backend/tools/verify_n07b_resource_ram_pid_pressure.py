"""Independently reconcile the N07B RAM/PID paired resource observation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
ARTIFACTS = BACKEND / "artifacts"
sys.path.insert(0, str(BACKEND))

from arena.contracts.jsonwire import load_wire  # noqa: E402
from arena.integration.corpus import PreparedPublicCorpus  # noqa: E402
from arena.integration.lanes import LaneAdmission  # noqa: E402
from arena.integration.runtime import runtime_source_hashes  # noqa: E402
from arena.integration.types import AdmissionLock  # noqa: E402
from tools.verify_n04 import sources as backend_sources  # noqa: E402
from tools import verify_n07b_p013_real_serial_concurrent as real_verifier  # noqa: E402
from tools.run_n07b_resource_ram_pid_pressure import (  # noqa: E402
    SCHEMA,
    SCOPE,
    analyze_phases,
    phase_plan,
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def inside_artifacts(path: Path) -> bool:
    try:
        path.resolve().relative_to(ARTIFACTS.resolve())
        return True
    except ValueError:
        return False


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
    if not inside_artifacts(observation_path):
        raise ValueError("OBSERVATION_OUTSIDE_PRIVATE_ARTIFACTS")
    if not all(path.is_file() for path in (lock_path, model_path, corpus_receipt_path, corpus_keys_path)):
        raise FileNotFoundError("VERIFIER_INPUT_FILE_MISSING")
    if not corpus_path.is_dir():
        raise FileNotFoundError("VERIFIER_CORPUS_DIRECTORY_MISSING")
    observation = json.loads(observation_path.read_bytes())
    if (
        observation.get("schema_version") != SCHEMA
        or observation.get("scope") != SCOPE
        or observation.get("result") not in {
            "RAM_PID_PRESSURE_PAIRED_OBSERVED",
            "OUTCOME_DRIFT_OBSERVED",
            "MODEL_RESPONSE_DRIFT_OBSERVED",
        }
        or observation.get("real_inference_performed") is not True
        or observation.get("real_public_jbb_used") is not True
        or observation.get("traffic_label") != "REAL_PUBLIC"
        or observation.get("defense_mode") != "INPUT"
        or observation.get("p011_complete") is not False
        or observation.get("p013_complete") is not False
        or observation.get("full_n07_acceptance") is not False
        or observation.get("full_arena_acceptance") is not False
        or observation.get("guarantee_tier_achieved") is not None
    ):
        raise ValueError("OBSERVATION_SCOPE_OR_STATUS_INVALID")
    if (
        digest(lock_path) != observation.get("lock_sha256")
        or digest(model_path) != observation.get("model_sha256")
        or digest(corpus_receipt_path) != observation.get("corpus_receipt_sha256")
    ):
        raise ValueError("ADMITTED_INPUT_HASH_MISMATCH")
    admission = load_wire(LaneAdmission, lock_path.read_bytes())
    if (
        model_path.name != admission.model_filename
        or digest(model_path) != admission.model_sha256
        or digest(model_path.parent / "LICENSE") != admission.model_license_sha256
        or digest(corpus_receipt_path) != admission.corpus_receipt_sha256
        or runtime_source_hashes() != admission.runtime_source_sha256
    ):
        raise ValueError("ADMISSION_MODEL_LICENSE_CORPUS_OR_RUNTIME_MISMATCH")
    cell_lock = lock_path.parent / "cell-admission.json"
    if not cell_lock.is_file() or digest(cell_lock) != admission.cell_admission_sha256:
        raise ValueError("N05_CELL_ADMISSION_HASH_MISMATCH")
    cell_admission = load_wire(AdmissionLock, cell_lock.read_bytes()).model_dump()
    if any(
        admission.model_dump().get(name) != value
        for name, value in cell_admission.items()
        if name not in {"schema_version", "claim_scope"}
    ):
        raise ValueError("N05_CELL_PROFILE_MISMATCH")
    public_corpus = PreparedPublicCorpus(
        corpus_path,
        corpus_receipt_path,
        corpus_keys_path,
        admission.corpus_receipt_sha256,
    )
    current_sources = backend_sources()
    if (
        observation.get("source_unchanged_during_run") is not True
        or observation.get("source_sha256") != current_sources
        or observation.get("source_sha256_after") != current_sources
    ):
        raise ValueError("MEASUREMENT_SOURCE_MANIFEST_MISMATCH")
    pre, post = observation.get("pre_run_container_check", {}), observation.get("post_run_container_check", {})
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
    scheduled_phases = phase_plan()
    if not isinstance(phases, list) or len(phases) != len(scheduled_phases):
        raise ValueError("PHASE_LIST_INVALID")
    output_root = observation_path.parent.resolve()
    for phase, scheduled in zip(phases, scheduled_phases, strict=True):
        if phase.get("phase") != scheduled["phase"]:
            raise ValueError("PHASE_ORDER_OR_NAME_MISMATCH")
        private_run = (BACKEND / phase.get("private_run_path", "")).resolve()
        if private_run != (output_root / scheduled["phase"]).resolve() or not inside_artifacts(private_run):
            raise ValueError("PRIVATE_N04_RUN_PATH_MISMATCH")
        summary_path = private_run / "summary.json"
        bundle_path = private_run / "public-evidence.zip"
        if (
            not summary_path.is_file()
            or digest(summary_path) != phase.get("n04_summary_sha256")
            or not bundle_path.is_file()
            or digest(bundle_path) != phase.get("public_bundle_sha256")
        ):
            raise ValueError("PRIVATE_N04_ARTIFACT_HASH_MISMATCH")
        summary = json.loads(summary_path.read_bytes())
        diagnostics = summary.get("verifier_result", {}).get("diagnostics", {})
        if (
            summary.get("run_label") != "REAL_PUBLIC"
            or summary.get("defense_mode") != "INPUT"
            or summary.get("real_model") is not True
            or summary.get("turns") != 6
            or summary.get("lane_count") != 3
            or summary.get("three_lane_acceptance") is not False
            or summary.get("n05_baseline_mechanisms_delivered") is not True
            or summary.get("model_dispatches", 0) <= 0
            or summary.get("model_dispatches") != sum(turn.get("model_execution") == "EXECUTED" for turn in phase.get("turns", []))
            or summary.get("verifier_exit_code") != 0
            or summary.get("verifier_result", {}).get("status") != "PASS_PUBLIC_EVIDENCE"
            or diagnostics.get("integrity") != "VALID_WITHIN_PROFILE"
            or diagnostics.get("turn_openings_verified") != 6
        ):
            raise ValueError("PRIVATE_N04_SUMMARY_ACCEPTANCE_MISMATCH")
        real_verifier._validate_private_results(
            phase=phase,
            summary=summary,
            lock_sha256=digest(lock_path),
        )
        selected = real_verifier._select_private_traces(phase["turns"], summary.get("model_trace", []))
        if real_verifier._overlap_summary(selected) != phase.get("model_overlap"):
            raise ValueError("MODEL_OVERLAP_RECOMPUTATION_MISMATCH")
        projection = phase.get("n04_cli", {})
        if (
            projection.get("run_label") != summary.get("run_label")
            or projection.get("defense_mode") != summary.get("defense_mode")
            or projection.get("real_model") is not summary.get("real_model")
            or projection.get("three_lane_acceptance") is not summary.get("three_lane_acceptance")
            or projection.get("n05_baseline_mechanisms_delivered") is not summary.get("n05_baseline_mechanisms_delivered")
            or projection.get("model_dispatches") != summary.get("model_dispatches")
            or projection.get("verifier_status") != summary.get("verifier_result", {}).get("status")
        ):
            raise ValueError("PUBLIC_N04_PROJECTION_MISMATCH")
        trust = json.loads((private_run / "trusted-context.json").read_bytes())
        real_verifier._rerun_private_verifier(private_run, trust)
        real_verifier._verify_private_events_and_model(
            private_run=private_run,
            phase=phase,
            trust=trust,
            public_corpus=public_corpus,
        )
    analysis = analyze_phases(phases)
    if analysis != observation.get("analysis"):
        raise ValueError("RESOURCE_ANALYSIS_RECOMPUTATION_MISMATCH")
    if (
        analysis.get("io_pressure_result") != "NOT_RUN_UNSUPPORTED_IO_MAX_OR_BACKING_DEVICE_MAP"
        or analysis.get("fairness_established") is not False
        or analysis.get("host_cpu_exclusivity_verified") is not False
    ):
        raise ValueError("RESOURCE_SCOPE_OVERCLAIM")
    return {
        "result": "PASS_SOURCE_AND_PRIVATE_N04_RESOURCE_RECONCILIATION",
        "scope": SCOPE,
        "source_file_count": len(current_sources),
        "source_sha256": observation["source_sha256"],
        "phase_count": analysis["phase_count"],
        "turn_count": analysis["turn_count"],
        "model_dispatch_count": analysis["model_dispatch_count"],
        "baseline_to_resource_pair_count": analysis["baseline_to_resource_pair_count"],
        "verdict_distribution": analysis["verdict_distribution"],
        "observed_verdict_count": analysis["observed_verdict_count"],
        "varied_defense_outcomes_observed": analysis["varied_defense_outcomes_observed"],
        "defense_outcome_coverage": analysis["defense_outcome_coverage"],
        "defense_outcome_drift_count": analysis["defense_outcome_drift_count"],
        "model_response_hash_drift_count": analysis["model_response_hash_drift_count"],
        "latency_change_summary": analysis["latency_change_summary"],
        "ram_pressure_observed": analysis["ram_pressure_observed"],
        "pid_pressure_observed_in_selected_model_cgroup": analysis["pid_pressure_observed_in_selected_model_cgroup"],
        "io_pressure_result": analysis["io_pressure_result"],
        "fairness_established": False,
        "p011_complete": False,
        "p013_complete": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("observation", "lock", "model", "corpus", "corpus-receipt", "corpus-keys"):
        parser.add_argument("--" + name, required=True, type=Path)
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
        code = str(exc)
        if not code.isascii() or not code.isupper():
            code = None
        print(json.dumps({"result": "FAIL_RECONCILIATION", "failure_type": type(exc).__name__, "failure_code": code}, sort_keys=True), flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
