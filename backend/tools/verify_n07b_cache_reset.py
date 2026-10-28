"""Collect source-bound evidence for N07B actual cache/reset controls.

Uses the already-prepared local model and defense image, real local inference
with synthetic markers, and a separately weakened session-unbind control.
No timing study, corpus traffic, deployment, or full-acceptance claim is made.
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
from uuid import uuid4

from verify_n04 import sources as backend_sources


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
EVIDENCE = ROOT / "memory files" / "hackathon" / "evidence"
N06_RECEIPT = EVIDENCE / "n06-completion-verification-2026-10-22.json"
N07A_RECEIPT = EVIDENCE / "n07-review-verification-2026-10-24.json"
SCOPE = "N07B_ACTUAL_REAL_CACHE_RESET_AND_WEAKENED_CONTEXT_CONTROL"
PRELIMINARY_RUNS = (
    {
        "path": "memory files/hackathon/evidence/n07b-cache-reset-preparation-attempt-01.log",
        "result": "PASS_PREPARATION",
        "note": "Documented N05 preparation succeeded before source-bound collection; the final collector repeats it into a new private directory.",
    },
    {
        "path": "memory files/hackathon/evidence/n07b-cache-reset-probe-attempt-01.log",
        "result": "FAIL_IMPORT",
        "note": "Initial runner imported ThreeLaneRuntime from the wrong module before starting any containers; corrected import is used in later attempts.",
    },
    {
        "path": "memory files/hackathon/evidence/n07b-cache-reset-probe-attempt-02.log",
        "result": "INCONCLUSIVE_WEAK_CONTROL",
        "note": "Defended reset passed, but one weakened-control query did not recall the retained marker; retained and superseded by the fixed three-query protocol.",
    },
    {
        "path": "memory files/hackathon/evidence/n07b-cache-reset-probe-attempt-03.log",
        "result": "PASS_PRELIMINARY",
        "note": "Fixed three-query weakened control detected the synthetic marker before the source-bound collection; collector repeats it.",
    },
)


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


def make_outputs_index(receipt_path: Path, receipt: dict[str, Any]) -> Path:
    files = {
        item["name"]: {"path": item["log_path"], "sha256": item["log_sha256"]}
        for item in receipt.get("command_results", [])
    }
    for item in receipt.get("preliminary_runs", []):
        files[Path(item["path"]).name] = {"path": item["path"], "sha256": item["sha256"]}
    path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    atomic_json(path, {
        "schema_version": "arena-n07b-cache-reset.v1",
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": digest(receipt_path),
        "files": files,
    })
    return path


def collect(args: argparse.Namespace) -> int:
    receipt_path = args.output.resolve()
    if receipt_path.parent != EVIDENCE.resolve():
        raise ValueError("RECEIPT_MUST_BE_IN_CANONICAL_MEMORY_EVIDENCE_DIRECTORY")
    index_path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    if receipt_path.exists() or index_path.exists():
        raise FileExistsError("OUTPUT_PATH_ALREADY_EXISTS_USE_A_NEW_ATTEMPT_PATH")
    offline_python = args.offline_python.resolve()
    if not offline_python.is_file():
        raise FileNotFoundError("OFFLINE_PYTHON_NOT_FOUND")
    if not args.cell_lock.is_file() or not args.model.is_file():
        raise FileNotFoundError("PREPARED_N04_LOCK_OR_LOCAL_MODEL_MISSING")
    private_output = args.private_output.resolve()
    private_preparation = args.private_preparation.resolve()
    artifact_root = (BACKEND / "artifacts").resolve()
    if private_output.exists() or private_preparation.exists():
        raise ValueError("NEW_PRIVATE_RUNTIME_AND_PREPARATION_OUTPUTS_REQUIRED")
    if not private_output.is_relative_to(artifact_root):
        raise ValueError("NEW_PRIVATE_RUNTIME_OUTPUT_REQUIRED_UNDER_BACKEND_ARTIFACTS")
    if not private_preparation.is_relative_to(artifact_root):
        raise ValueError("NEW_PRIVATE_PREPARATION_OUTPUT_REQUIRED_UNDER_BACKEND_ARTIFACTS")

    prior = []
    for item in PRELIMINARY_RUNS:
        path = ROOT / item["path"]
        if not path.is_file():
            raise FileNotFoundError("PRELIMINARY_RUN_LOG_MISSING: " + item["path"])
        prior.append({**item, "sha256": digest(path)})

    n06_unchanged = historical_receipt_matches(N06_RECEIPT)
    n07a_unchanged = historical_receipt_matches(N07A_RECEIPT)
    before = source_hashes()
    prepared_lock = private_preparation / "admission.json"
    probe_observation = private_output / "observation.json"
    receipt: dict[str, Any] = {
        "schema_version": "arena-n07b-cache-reset.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": SCOPE,
        "result": "FAIL",
        "collector_state": "IN_PROGRESS",
        "active_command": None,
        "source_sha256": before,
        "source_file_count": len(before),
        "n06_original_sources_unchanged": n06_unchanged,
        "n07a_source_files_unchanged": n07a_unchanged,
        "source_unchanged_during_checks": False,
        "model_kind": "REAL_LOCAL_MODEL_SYNTHETIC_CANARIES",
        "real_inference_performed": True,
        "real_corpus_used": False,
        "timing_measurement_performed": False,
        "production_runtime_sources_changed": False,
        "wire_contract_changed": False,
        "shared_signing_bytes_changed": False,
        "frontend_changed": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
        "preliminary_runs": prior,
        "private_artifacts": {
            "preparation_output": private_preparation.relative_to(BACKEND).as_posix(),
            "runtime_output": private_output.relative_to(BACKEND).as_posix(),
            "committed": False,
        },
        "command_results": [],
    }

    def checkpoint() -> None:
        atomic_json(receipt_path, receipt)

    def execute(name: str, command: list[str], cwd: Path) -> None:
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
            "log_path": log.relative_to(ROOT).as_posix(),
            "log_sha256": digest(log),
            "summary": next((line.strip() for line in reversed(lines) if line.strip()), ""),
        }
        receipt["command_results"].append(item)
        receipt["active_command"] = None
        checkpoint()
        print(json.dumps({key: item[key] for key in ("name", "exit_code", "summary")}), flush=True)
        if proc.returncode:
            raise RuntimeError("REQUIRED_COMMAND_FAILED_" + name.upper().replace("-", "_"))

    try:
        execute("prepare-n05", [
            sys.executable, "tools/prepare_n05.py",
            "--cell-lock", str(args.cell_lock.resolve()),
            "--output", str(private_preparation),
        ], BACKEND)
        execute("actual-cache-reset-probe", [
            sys.executable, "tools/run_n07b_cache_reset_probe.py",
            "--lock", str(prepared_lock),
            "--model", str(args.model.resolve()),
            "--output", str(private_output),
        ], BACKEND)
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
            "model_cpuset_count": len(prep_values[0]["model_cpusets"]),
            "defense_cpuset_count": len(prep_values[0]["defense_cpuset"].split(",")),
            "observed_mem_available_bytes": prep_values[0]["observed_mem_available_bytes"],
            "lock_sha256": digest(prepared_lock),
        }

        raw_observation = json.loads(probe_observation.read_bytes())
        probe_log = ROOT / receipt["command_results"][1]["log_path"]
        # The runner's final line is a sanitized summary. The private artifact
        # carries the same observations plus exact source/model/lock hashes.
        summary_lines = [
            json.loads(line) for line in probe_log.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip().startswith("{")
        ]
        if len(summary_lines) != 1:
            raise ValueError("CACHE_RESET_SANITIZED_OBSERVATION_MISSING_OR_DUPLICATED")
        summary = summary_lines[0]
        observed = raw_observation
        defended, weak = observed.get("defended_reset", {}), observed.get("weakened_control", {})
        trials = weak.get("trials", [])
        erase_acks = defended.get("server_erase_acks")
        erase_ack = (
            erase_acks[0]
            if isinstance(erase_acks, list) and len(erase_acks) == 1 and isinstance(erase_acks[0], dict)
            else {}
        )
        if (
            summary.get("result") != observed.get("result")
            or summary.get("scope") != observed.get("scope")
            or summary.get("defended_reset") != defended
            or summary.get("weakened_control") != weak
            or observed.get("schema_version") != "arena-n07b-cache-reset-observation.v1"
            or observed.get("scope") != SCOPE
            or observed.get("result") != "PASS"
            or observed.get("transport") != "LOCKED_LOCAL_THREE_LANE_DOCKER_RUNTIME"
            or observed.get("model_kind") != "REAL_LOCAL_QWEN_MODEL_SYNTHETIC_CANARIES"
            or observed.get("lane_count") != 3
            or observed.get("real_inference_performed") is not True
            or observed.get("real_corpus_used") is not False
            or observed.get("timing_measurement_performed") is not False
            or observed.get("full_n07_acceptance") is not False
            or observed.get("full_arena_acceptance") is not False
            or observed.get("guarantee_tier_achieved") is not None
            or defended.get("seed_echoed_marker") is not True
            or defended.get("same_session_recalled_marker") is not True
            or defended.get("server_erase_ack_count") != 1
            or erase_ack.get("id_slot") != 0
            or type(erase_ack.get("n_erased")) is not int
            or erase_ack["n_erased"] < 0
            or defended.get("container_recreated_before_reuse") is not True
            or defended.get("post_reset_marker_absent") is not True
            or weak.get("seed_echoed_marker") is not True
            or weak.get("container_reused_without_reset") is not True
            or weak.get("fixed_query_count") != 3
            or len(trials) != 3
            or weak.get("weakened_control_detected") is not True
            or not any(item.get("marker_recalled") is True for item in trials)
        ):
            raise ValueError("REAL_CACHE_RESET_OR_WEAKENED_CONTROL_OBSERVATION_INVALID")
        receipt["observations"] = {
            "defended_reset": defended,
            "weakened_control": weak,
            "weakened_control_scope": "RETAINED_CLIENT_SIDE_LANE_HISTORY_WITHOUT_ADAPTER_RESET_SLOT_ERASE_OR_CONTAINER_RECREATION",
            "sanitized_runtime_observation_sha256": digest(probe_observation),
            "private_artifact_omitted": True,
        }

        memory_log = next(
            ROOT / item["log_path"] for item in receipt["command_results"]
            if item["name"] == "memory-check-pre-reconciliation"
        )
        memory_result = None
        for line in reversed(memory_log.read_text(encoding="utf-8", errors="replace").splitlines()):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if value.get("result") == "PASS" and isinstance(value.get("checks"), int):
                memory_result = {key: value[key] for key in ("result", "checks", "revision", "questions", "objectives")}
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
            receipt["changed_source_paths"] = sorted(path for path in before if before[path] != after.get(path))
            raise ValueError("SOURCE_CHANGED_DURING_CHECKS")
        if not n06_unchanged or not n07a_unchanged:
            raise ValueError("HISTORICAL_SOURCE_RECEIPT_MISMATCH")
        receipt["source_sha256"] = after
        receipt["source_file_count"] = len(after)
        receipt["collector_state"] = "COMPLETED"
        receipt["result"] = "PASS"
        receipt["active_command"] = None
        checkpoint()
        outputs = make_outputs_index(receipt_path, receipt)
        print(json.dumps({
            "result": receipt["result"],
            "scope": receipt["scope"],
            "receipt": receipt_path.relative_to(ROOT).as_posix(),
            "receipt_sha256": digest(receipt_path),
            "outputs_index": outputs.relative_to(ROOT).as_posix(),
            "outputs_index_sha256": digest(outputs),
            "source_file_count": receipt["source_file_count"],
            "pytest_counts": receipt["pytest_counts"],
            "pytest_skipped_counts": receipt["pytest_skipped_counts"],
        }), flush=True)
        return 0
    except Exception as exc:
        receipt["collector_state"] = "FAILED"
        receipt["result"] = "FAIL"
        receipt["failure"] = type(exc).__name__ + ": " + str(exc)
        receipt["active_command"] = None
        checkpoint()
        if not index_path.exists():
            make_outputs_index(receipt_path, receipt)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cell-lock", required=True, type=Path)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--private-preparation", required=True, type=Path)
    parser.add_argument("--private-output", required=True, type=Path)
    parser.add_argument(
        "--offline-python",
        type=Path,
        default=BACKEND / "artifacts" / "repro-env" / "Scripts" / "python.exe",
    )
    try:
        return collect(parser.parse_args())
    except (OSError, ValueError, FileNotFoundError, RuntimeError, subprocess.SubprocessError) as exc:
        print("N07B cache/reset collection FAILED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
