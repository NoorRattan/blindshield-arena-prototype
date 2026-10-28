"""Collect a source-bound actual-mTLS role-view observation for N07B.

This runs loopback HTTPS/mTLS synthetic fixtures and backend regressions. It is
not an inference, timing-channel, deployment, or full N07 acceptance receipt.
Each invocation needs a new output path so failed attempts stay inspectable.
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
ACTIVE = ROOT / "memory files" / "hackathon"
EVIDENCE = ACTIVE / "evidence"
N06_RECEIPT = EVIDENCE / "n06-completion-verification-2026-10-22.json"
N07A_RECEIPT = EVIDENCE / "n07-review-verification-2026-10-24.json"

SOURCE_FILES = (
    "tools/check_memory.py",
    "backend/tools/verify_n07b_mtls_role_observations.py",
    "backend/tests/integration/test_n07b_mtls_role_observations.py",
    "backend/tests/integration/test_n06_execution.py",
    "backend/tests/integration/test_n06_transport.py",
    "backend/tests/integration/test_n04.py",
    "backend/src/arena/broker/core.py",
    "backend/src/arena/broker/server.py",
    "backend/src/arena/broker/store.py",
    "backend/src/arena/contracts/api.py",
    "backend/src/arena/contracts/common.py",
    "backend/src/arena/contracts/crypto.py",
    "backend/src/arena/contracts/evidence.py",
    "backend/src/arena/execution/lab.py",
    "backend/src/arena/execution/policy.py",
    "backend/src/arena/execution/queue.py",
    "backend/src/arena/execution/transport.py",
    "backend/src/arena/execution/worker.py",
    "backend/src/arena/integration/artifacts.py",
    "backend/src/arena/integration/controller.py",
    "backend/src/arena/ports.py",
)

RETAINED_ATTEMPTS = (
    (
        "memory files/hackathon/evidence/n07b-mtls-role-observations-authoring-failure-01.log",
        "FAIL",
        "Initial fixture expectation assumed integrity VALID; observed RUNNING/PENDING.",
    ),
    (
        "memory files/hackathon/evidence/n07b-mtls-role-observations-authoring-failure-02.log",
        "FAIL",
        "Initial durable snapshot used a nonexistent Event.status field; corrected to outcome_code.",
    ),
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


def hashes(paths: tuple[str, ...]) -> dict[str, str]:
    result = {}
    for relative in paths:
        path = ROOT / relative
        if not path.is_file():
            raise FileNotFoundError(relative)
        result[relative] = sha256_file(path)
    return result


def historical_source_matches(relative: str, expected: str) -> bool:
    path = (ROOT / relative).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        return False
    if sha256_file(path) == expected:
        return True
    backend_path = relative.removeprefix("backend/")
    snapshot = BACKEND / "evidence" / "source-snapshots" / (expected + ".txt")
    return relative.startswith("backend/") and snapshot.is_file() and sha256_file(snapshot) == expected


def historical_receipt_matches(receipt_path: Path) -> bool:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    source_hashes = receipt.get("source_sha256", {})
    return bool(source_hashes) and all(
        historical_source_matches(relative, expected)
        for relative, expected in source_hashes.items()
    )


def write_output_index(receipt_path: Path, receipt: dict[str, Any]) -> Path:
    index_path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    files = {
        item["name"]: {"path": item["log_path"], "sha256": item["log_sha256"]}
        for item in receipt.get("command_results", [])
        if item.get("log_path") and item.get("log_sha256")
    }
    for item in receipt.get("retained_attempts", []):
        files[Path(item["path"]).name] = {"path": item["path"], "sha256": item["sha256"]}
    index = {
        "schema_version": "arena-n07b-mtls-role-observations.v1",
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": sha256_file(receipt_path),
        "files": files,
    }
    atomic_json(index_path, index)
    return index_path


def collect(args: argparse.Namespace) -> int:
    receipt_path = args.output.resolve()
    if receipt_path.parent != EVIDENCE.resolve():
        raise ValueError("RECEIPT_MUST_BE_IN_CANONICAL_MEMORY_EVIDENCE_DIRECTORY")
    if receipt_path.exists():
        raise FileExistsError("OUTPUT_PATH_ALREADY_EXISTS_USE_A_NEW_ATTEMPT_PATH")
    output_index = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    if output_index.exists():
        raise FileExistsError("OUTPUT_INDEX_ALREADY_EXISTS_USE_A_NEW_ATTEMPT_PATH")
    offline_python = args.offline_python.resolve()
    if not offline_python.is_file():
        raise FileNotFoundError("OFFLINE_PYTHON_NOT_FOUND")

    retained = []
    for relative, result, reason in RETAINED_ATTEMPTS:
        path = ROOT / relative
        if not path.is_file():
            raise FileNotFoundError("RETAINED_AUTHORING_ATTEMPT_MISSING: " + relative)
        retained.append({"path": relative, "result": result, "reason": reason, "sha256": sha256_file(path)})

    n06_unchanged = historical_receipt_matches(N06_RECEIPT)
    n07a_unchanged = historical_receipt_matches(N07A_RECEIPT)
    before = hashes(SOURCE_FILES)
    receipt: dict[str, Any] = {
        "schema_version": "arena-n07b-mtls-role-observations.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "N07B_ACTUAL_MTLS_ROLE_SCOPED_STATUS_FEEDBACK_OBSERVATIONS",
        "result": "FAIL",
        "collector_state": "IN_PROGRESS",
        "active_command": None,
        "source_sha256": before,
        "n06_original_sources_unchanged": n06_unchanged,
        "n07a_source_files_unchanged": n07a_unchanged,
        "source_unchanged_during_checks": False,
        "model_kind": "SYNTHETIC_COMPONENT_FIXTURE",
        "real_inference_performed": False,
        "production_runtime_sources_changed": False,
        "wire_contract_changed": False,
        "shared_signing_bytes_changed": False,
        "frontend_changed": False,
        "full_n07_acceptance": False,
        "full_arena_acceptance": False,
        "guarantee_tier_achieved": None,
        "retained_attempts": retained,
        "command_results": [],
    }

    def checkpoint() -> None:
        atomic_json(receipt_path, receipt)

    def execute(name: str, command: list[str], cwd: Path) -> None:
        log_path = receipt_path.with_name(receipt_path.stem + "-" + name + ".log")
        if log_path.exists():
            raise FileExistsError("COMMAND_LOG_ALREADY_EXISTS: " + str(log_path))
        receipt["active_command"] = name
        checkpoint()
        with log_path.open("xb") as stream:
            proc = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=False)
            stream.flush()
            os.fsync(stream.fileno())
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
        item = {
            "name": name,
            "command": command,
            "exit_code": proc.returncode,
            "log_path": log_path.relative_to(ROOT).as_posix(),
            "log_sha256": sha256_file(log_path),
            "summary": next((line.strip() for line in reversed(lines) if line.strip()), ""),
        }
        receipt["command_results"].append(item)
        receipt["active_command"] = None
        checkpoint()
        print(json.dumps({key: item[key] for key in ("name", "exit_code", "summary")}), flush=True)
        if proc.returncode:
            raise RuntimeError("REQUIRED_COMMAND_FAILED_" + name.upper().replace("-", "_"))

    try:
        execute("focused-mtls-role-matrix", [
            sys.executable, "-m", "pytest", "-q", "-s", "-v", "-W", "error",
            "tests/integration/test_n07b_mtls_role_observations.py",
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

        focused_log = ROOT / receipt["command_results"][0]["log_path"]
        marker = "N07B_MTLS_ROLE_OBSERVATIONS "
        lines = focused_log.read_text(encoding="utf-8", errors="replace").splitlines()
        found = [line[line.index(marker) + len(marker):] for line in lines if marker in line]
        if len(found) != 1:
            raise ValueError("N07B_MTLS_ROLE_OBSERVATION_MISSING_OR_DUPLICATED")
        observation = json.loads(found[0])
        if (observation.get("scope") != receipt["scope"] or
                observation.get("transport") != "LOCAL_HTTPS_MUTUAL_TLS" or
                observation.get("model_kind") != receipt["model_kind"] or
                observation.get("full_n07_acceptance") is not False or
                observation.get("full_arena_acceptance") is not False or
                len(observation.get("states", [])) != 3 or
                any(item.get("actual_mtls_gets") != 6 or
                    item.get("reads_side_effect_free") is not True or
                    item.get("same_fixed_body_across_endpoints_and_states") is not True
                    for item in observation["states"])):
            raise ValueError("N07B_MTLS_ROLE_OBSERVATION_SCOPE_OR_MATRIX_INVALID")
        receipt["observations"] = {"actual_mtls_role_matrix": observation}

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

        receipt["focused_test_count"] = 1
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

        after = hashes(SOURCE_FILES)
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
        index_path = write_output_index(receipt_path, receipt)
        print(json.dumps({
            "result": receipt["result"],
            "receipt": receipt_path.relative_to(ROOT).as_posix(),
            "receipt_sha256": sha256_file(receipt_path),
            "outputs_index": index_path.relative_to(ROOT).as_posix(),
            "outputs_index_sha256": sha256_file(index_path),
            "focused_test_count": receipt["focused_test_count"],
            "pytest_counts": receipt["pytest_counts"],
            "pytest_skipped_counts": receipt["pytest_skipped_counts"],
            "source_file_count": receipt["source_file_count"],
        }), flush=True)
        return 0
    except Exception as exc:
        receipt["collector_state"] = "FAILED"
        receipt["result"] = "FAIL"
        receipt["failure"] = type(exc).__name__ + ": " + str(exc)
        receipt["active_command"] = None
        checkpoint()
        if not output_index.exists():
            write_output_index(receipt_path, receipt)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--offline-python", type=Path,
        default=BACKEND / "artifacts" / "repro-env" / "Scripts" / "python.exe",
    )
    args = parser.parse_args()
    try:
        return collect(args)
    except (OSError, ValueError, FileNotFoundError, RuntimeError, subprocess.SubprocessError) as exc:
        print("N07B mTLS role-observation collection FAILED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
