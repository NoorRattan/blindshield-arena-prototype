"""Run and publish the bounded N07B queue-publication process-death slice.

This collector executes synthetic-component integration tests and backend
regressions. It does not run inference, timing calibration, or full N07 probes.
Use a new output path for every attempt so failures remain inspectable.
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


ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
N06_RECEIPT = ROOT / "memory files/hackathon/evidence/n06-completion-verification-2026-10-22.json"
N07A_RECEIPT = ROOT / "memory files/hackathon/evidence/n07-review-verification-2026-10-24.json"

SOURCE_FILES = (
    "tools/check_memory.py",
    "backend/tools/verify_n07b_integrated_ack.py",
    "backend/tools/verify_n07b_queue_publication.py",
    "backend/tests/integration/test_n07b_integrated_faults.py",
    "backend/tests/integration/test_n07b_queue_publication.py",
    "backend/tests/integration/test_n06_execution.py",
    "backend/tests/integration/test_n04.py",
    "backend/src/arena/broker/config.py",
    "backend/src/arena/broker/core.py",
    "backend/src/arena/broker/store.py",
    "backend/src/arena/contracts/api.py",
    "backend/src/arena/contracts/common.py",
    "backend/src/arena/contracts/crypto.py",
    "backend/src/arena/contracts/evidence.py",
    "backend/src/arena/contracts/transport_profile.py",
    "backend/src/arena/execution/policy.py",
    "backend/src/arena/execution/queue.py",
    "backend/src/arena/execution/worker.py",
    "backend/src/arena/integration/artifacts.py",
    "backend/src/arena/integration/controller.py",
    "backend/src/arena/integration/types.py",
    "backend/src/arena/ports.py",
    "backend/src/arena/recorder/canonical.py",
    "backend/src/arena/recorder/recorder.py",
    "backend/src/arena/verifier/archive.py",
    "backend/src/arena/verifier/rules.py",
    "backend/src/arena/witness/authority.py",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    with temp.open("xb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def hashes(paths: tuple[str, ...] | list[str]) -> dict[str, str]:
    result = {}
    for relative in paths:
        path = ROOT / relative
        if not path.is_file():
            raise FileNotFoundError(relative)
        result[relative] = sha256_file(path)
    return result


def compare_hashes(expected: dict[str, str]) -> tuple[bool, list[str]]:
    mismatches = []
    for relative, digest in expected.items():
        path = ROOT / relative
        if not path.is_file() or sha256_file(path) != digest:
            mismatches.append(relative)
    return not mismatches, mismatches


def write_output_index(receipt_path: Path, receipt: dict[str, Any]) -> Path:
    index_path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    index = {
        "schema_version": "arena-n07b-queue-publication.v1",
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": sha256_file(receipt_path),
        "files": {
            item["name"]: {"path": item["log_path"], "sha256": item["log_sha256"]}
            for item in receipt["command_results"]
            if item.get("log_path") and item.get("log_sha256")
        },
    }
    atomic_json(index_path, index)
    return index_path


def collect(args: argparse.Namespace) -> int:
    receipt_path = args.output.resolve()
    if receipt_path.exists():
        raise FileExistsError("OUTPUT_PATH_ALREADY_EXISTS_USE_A_NEW_ATTEMPT_PATH")
    index_path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    if index_path.exists():
        raise FileExistsError("OUTPUT_INDEX_ALREADY_EXISTS_USE_A_NEW_ATTEMPT_PATH")
    offline_python = args.offline_python.resolve()
    if not offline_python.is_file():
        raise FileNotFoundError("OFFLINE_PYTHON_NOT_FOUND")

    old_n06 = json.loads(N06_RECEIPT.read_text(encoding="utf-8"))
    old_n07a = json.loads(N07A_RECEIPT.read_text(encoding="utf-8"))
    n06_ok, n06_mismatches = compare_hashes(old_n06.get("source_sha256", {}))
    n07a_ok, n07a_mismatches = compare_hashes(old_n07a.get("source_sha256", {}))
    before = hashes(SOURCE_FILES)
    receipt: dict[str, Any] = {
        "schema_version": "arena-n07b-queue-publication.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "N07B_INTEGRATED_QUEUE_PUBLICATION_PROCESS_DEATH_WINDOW",
        "result": "FAIL",
        "collector_state": "IN_PROGRESS",
        "active_command": None,
        "source_sha256": before,
        "source_unchanged_during_checks": False,
        "n06_original_sources_unchanged": n06_ok,
        "n06_source_mismatches": n06_mismatches,
        "n06_original_receipt_sha256": sha256_file(N06_RECEIPT),
        "n07a_source_files_unchanged": n07a_ok,
        "n07a_source_mismatches": n07a_mismatches,
        "n07a_receipt_sha256": sha256_file(N07A_RECEIPT),
        "historical_receipts_rewritten": False,
        "command_results": [],
        "observations": None,
        "retained_attempts": [],
        "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
        "real_inference_performed": False,
        "wire_contract_changed": False,
        "shared_signing_bytes_changed": False,
        "frontend_changed": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
        "outputs_index": index_path.relative_to(ROOT).as_posix(),
    }

    work = BACKEND / "artifacts" / "n07b-runs" / receipt_path.stem
    work.mkdir(parents=True, exist_ok=False)

    def checkpoint() -> None:
        atomic_json(receipt_path, receipt)
        atomic_json(work / "progress.json", receipt)

    def execute(name: str, command: list[str], *, cwd: Path = BACKEND, timeout: int = 1800) -> None:
        receipt["active_command"] = name
        checkpoint()
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=timeout)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            code = 124
            raw = (error.stdout or b"") + (error.stderr or b"") + b"\nCOMMAND_TIMEOUT\n"
        log_path = receipt_path.with_name(receipt_path.stem + f"-{name}.log")
        with log_path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        lines = raw.decode(errors="replace").strip().splitlines()
        item = {
            "name": name,
            "command": command,
            "working_directory": cwd.relative_to(ROOT).as_posix(),
            "exit_code": code,
            "log_path": log_path.relative_to(ROOT).as_posix(),
            "log_sha256": sha256_file(log_path),
            "summary": lines[-1] if lines else "",
        }
        receipt["command_results"].append(item)
        receipt["active_command"] = None
        checkpoint()
        print(json.dumps({key: item[key] for key in ("name", "exit_code", "summary")}), flush=True)
        if code:
            raise RuntimeError("REQUIRED_COMMAND_FAILED_" + name.upper().replace("-", "_"))

    try:
        focused = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-s",
            "-v",
            "-W",
            "error",
            "tests/integration/test_n07b_integrated_faults.py",
            "tests/integration/test_n07b_queue_publication.py",
            "tests/integration/test_n06_execution.py::test_lost_target_ack_is_unknown_invalid_and_never_retried",
            "tests/integration/test_n06_execution.py::test_controller_explicit_predispatch_rejection_is_not_falsely_unknown",
            "tests/integration/test_n04.py::test_lost_witness_close_ack_retries_exact_checkpoint_without_new_execution",
        ]
        execute("focused-faults-and-truth-controls", focused)
        execute("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"])
        execute("pytest-offline", [str(offline_python), "-m", "pytest", "-q", "-W", "error"])
        for name, command in (
            ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
            ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
            ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
            ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
            ("dependencies", [sys.executable, "-m", "pip", "check"]),
        ):
            execute(name, command)
        execute("memory-check", [sys.executable, "tools/check_memory.py"], cwd=ROOT)

        focused_log = ROOT / receipt["command_results"][0]["log_path"]
        marker = "N07B_OBSERVED "
        lines = focused_log.read_text(encoding="utf-8", errors="replace").splitlines()
        found = next((line[line.index(marker) + len(marker):] for line in lines if marker in line), None)
        if found is None:
            raise ValueError("N07B_STRUCTURED_OBSERVATION_MISSING")
        queue_marker = "N07B_QUEUE_PUBLICATION_OBSERVED "
        queue_found = next((line[line.index(queue_marker) + len(queue_marker):] for line in lines if queue_marker in line), None)
        if queue_found is None:
            raise ValueError("N07B_QUEUE_PUBLICATION_OBSERVATION_MISSING")
        receipt["observations"] = {
            "terminal_ack": json.loads(found),
            "queue_publication": json.loads(queue_found),
        }
        receipt["focused_test_count"] = next(
            (int(match.group(1)) for item in receipt["command_results"]
             if item["name"] == "focused-faults-and-truth-controls"
             for match in [re.search(r"(\d+) passed", item["summary"])] if match),
            0,
        )
        receipt["pytest_counts"] = [
            int(match.group(1))
            for item in receipt["command_results"]
            if item["name"].startswith("pytest-")
            for match in [re.search(r"(\d+) passed", item["summary"])]
            if match
        ]
        receipt["pytest_skipped_counts"] = [
            int(match.group(1)) if match else 0
            for item in receipt["command_results"]
            if item["name"].startswith("pytest-")
            for match in [re.search(r"(\d+) skipped", item["summary"])]
        ]
        receipt["subtest_counts"] = [
            int(match.group(1)) if match else 0
            for item in receipt["command_results"]
            if item["name"].startswith("pytest-")
            for match in [re.search(r"(\d+) subtests passed", item["summary"])]
        ]

        retained = []
        for name in (
            "pytest-collection-unknown-mark.log",
            "pytest-integrated-env-missing-witness.log",
            "pytest-close-pending-integrity-expectation.log",
            "authoring-attempt-01-failure.txt",
        ):
            attempt_root = (
                BACKEND / "artifacts" / "n07b-queue-publication-attempts"
                if name == "authoring-attempt-01-failure.txt"
                else BACKEND / "artifacts" / "n07b-attempts"
            )
            path = attempt_root / name
            if path.is_file():
                retained.append({
                    "path": path.relative_to(ROOT).as_posix(),
                    "sha256": sha256_file(path),
                    "result": "FAIL",
                })
        receipt["retained_attempts"] = retained
        after = hashes(SOURCE_FILES)
        unchanged = before == after
        tests_pass = (
            receipt["focused_test_count"] == 5
            and receipt["pytest_counts"] == [383, 383]
            and receipt["pytest_skipped_counts"] == [1, 1]
            and receipt["subtest_counts"] == [14, 14]
        )
        result = "PASS" if n06_ok and n07a_ok and unchanged and tests_pass else "FAIL"
        receipt.update(
            result=result,
            collector_state="COMPLETED" if result == "PASS" else "FAILED",
            active_command=None,
            finished_at_utc=datetime.now(timezone.utc).isoformat(),
            source_sha256_after=after,
            source_unchanged_during_checks=unchanged,
        )
        checkpoint()
        write_output_index(receipt_path, receipt)
        print(json.dumps({
            "result": receipt["result"],
            "collector_state": receipt["collector_state"],
            "pytest_counts": receipt.get("pytest_counts"),
            "n06_original_sources_unchanged": n06_ok,
            "n07a_source_files_unchanged": n07a_ok,
            "full_n07_acceptance": False,
        }), flush=True)
        return 0 if result == "PASS" else 1
    except Exception as error:
        receipt.update(
            result="FAIL",
            collector_state="FAILED",
            active_command=None,
            error_type=type(error).__name__,
        )
        checkpoint()
        write_output_index(receipt_path, receipt)
        print(json.dumps({"result": "FAIL", "error_type": type(error).__name__}), flush=True)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline-python", type=Path, required=True)
    return collect(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
