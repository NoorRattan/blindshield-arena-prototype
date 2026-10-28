"""Collect source-bound evidence for the N07B mTLS truncated-body boundary.

The probe sends a valid synthetic turn body over local HTTPS/mTLS, declares one
additional body byte, and emits TLS close-notify. This is not real inference,
deployment, full-N07, or full-arena acceptance evidence.
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
EVIDENCE = ROOT / "memory files" / "hackathon" / "evidence"
N06_RECEIPT = EVIDENCE / "n06-completion-verification-2026-10-22.json"
N07A_RECEIPT = EVIDENCE / "n07-review-verification-2026-10-24.json"
SCOPE = "N07B_ACTUAL_MTLS_TRUNCATED_BODY_DENIAL"
PRELIMINARY_RUNS = (
    "memory files/hackathon/evidence/n07b-mtls-truncated-body-attempt-01.log",
    "memory files/hackathon/evidence/n07b-mtls-truncated-body-attempt-02.log",
)

SOURCE_FILES = (
    "tools/check_memory.py",
    "backend/tools/verify_n07b_mtls_truncated_body.py",
    "backend/tests/integration/test_n07b_mtls_truncated_body.py",
    "backend/tests/integration/test_n06_execution.py",
    "backend/tests/integration/test_n04.py",
    "backend/src/arena/broker/config.py",
    "backend/src/arena/broker/core.py",
    "backend/src/arena/broker/server.py",
    "backend/src/arena/broker/store.py",
    "backend/src/arena/contracts/api.py",
    "backend/src/arena/contracts/common.py",
    "backend/src/arena/contracts/crypto.py",
    "backend/src/arena/contracts/evidence.py",
    "backend/src/arena/contracts/jsonwire.py",
    "backend/src/arena/contracts/transport_profile.py",
    "backend/src/arena/execution/lab.py",
    "backend/src/arena/execution/policy.py",
    "backend/src/arena/execution/queue.py",
    "backend/src/arena/execution/transport.py",
    "backend/src/arena/execution/worker.py",
    "backend/src/arena/integration/artifacts.py",
    "backend/src/arena/integration/controller.py",
    "backend/src/arena/ports.py",
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


def source_hashes() -> dict[str, str]:
    result = {}
    for relative in SOURCE_FILES:
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
    snapshot = BACKEND / "evidence" / "source-snapshots" / (expected + ".txt")
    return (relative.startswith("backend/") or relative == "tools/check_memory.py") and \
        snapshot.is_file() and sha256_file(snapshot) == expected


def historical_receipt_matches(receipt_path: Path) -> bool:
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    sources = receipt.get("source_sha256", {})
    return bool(sources) and all(
        historical_source_matches(relative, expected)
        for relative, expected in sources.items()
    )


def output_index(receipt_path: Path, receipt: dict[str, Any]) -> Path:
    files = {
        item["name"]: {"path": item["log_path"], "sha256": item["log_sha256"]}
        for item in receipt.get("command_results", [])
    }
    for item in receipt.get("preliminary_runs", []):
        files[Path(item["path"]).name] = {
            "path": item["path"], "sha256": item["sha256"]
        }
    path = receipt_path.with_name(receipt_path.stem + "-outputs.json")
    atomic_json(path, {
        "schema_version": "arena-n07b-mtls-truncated-body.v1",
        "receipt": receipt_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": sha256_file(receipt_path),
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

    preliminary = []
    for index, relative in enumerate(PRELIMINARY_RUNS, start=1):
        path = ROOT / relative
        if not path.is_file():
            raise FileNotFoundError("PRELIMINARY_RUN_LOG_MISSING: " + relative)
        preliminary.append({
            "path": relative,
            "result": "PASS_SUPERSEDED" if index == 1 else "PASS_PRELIMINARY",
            "scope_note": (
                "Initial short-body request used malformed partial JSON; retained as an early transport check and superseded by the valid JSON body in attempts 02 and the final collection."
                if index == 1 else
                "Focused valid JSON body probe passed before the source-bound full collection; the collector below repeats it."
            ),
            "sha256": sha256_file(path),
        })

    n06_unchanged = historical_receipt_matches(N06_RECEIPT)
    n07a_unchanged = historical_receipt_matches(N07A_RECEIPT)
    before = source_hashes()
    receipt: dict[str, Any] = {
        "schema_version": "arena-n07b-mtls-truncated-body.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "base_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "scope": SCOPE,
        "result": "FAIL",
        "collector_state": "IN_PROGRESS",
        "active_command": None,
        "source_sha256": before,
        "source_file_count": len(before),
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
        "preliminary_runs": preliminary,
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
            proc = subprocess.run(
                command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=False
            )
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
        execute("focused-truncated-body", [
            sys.executable, "-m", "pytest", "-q", "-s", "-v", "-W", "error",
            "tests/integration/test_n07b_mtls_truncated_body.py",
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
        marker = "N07B_MTLS_TRUNCATED_BODY "
        found = [
            line[line.index(marker) + len(marker):]
            for line in focused_log.read_text(encoding="utf-8", errors="replace").splitlines()
            if marker in line
        ]
        if len(found) != 1:
            raise ValueError("N07B_MTLS_TRUNCATED_BODY_OBSERVATION_MISSING_OR_DUPLICATED")
        observation = json.loads(found[0])
        if (
            observation.get("scope") != SCOPE
            or observation.get("transport") != "LOCAL_HTTPS_MUTUAL_TLS"
            or observation.get("model_kind") != "SYNTHETIC_COMPONENT_FIXTURE"
            or observation.get("fixture_state") != ["RUNNING", "PENDING"]
            or observation.get("declared_content_length") != observation.get("transmitted_body_bytes", 0) + 1
            or observation.get("transmitted_body_bytes", 0) <= 0
            or observation.get("tls_eof") != "ORDERLY_CLOSE_NOTIFY"
            or observation.get("http_status") != 400
            or observation.get("envelope_status") != "ERROR"
            or observation.get("error_code") != "INVALID_SCHEMA"
            or observation.get("response_bytes") != 4096
            or observation.get("captured_snapshot_unchanged") is not True
            or observation.get("real_inference_performed") is not False
            or observation.get("full_n07_acceptance") is not False
            or observation.get("full_arena_acceptance") is not False
            or observation.get("guarantee_tier_achieved") is not None
        ):
            raise ValueError("N07B_MTLS_TRUNCATED_BODY_OBSERVATION_SCOPE_OR_RESULT_INVALID")
        receipt["observations"] = {"truncated_body": observation}

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
                memory_result = {
                    key: value[key]
                    for key in ("result", "checks", "revision", "questions", "objectives")
                }
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

        after = source_hashes()
        receipt["source_unchanged_during_checks"] = before == after
        if not receipt["source_unchanged_during_checks"]:
            receipt["changed_source_paths"] = sorted(
                path for path in before if before[path] != after.get(path)
            )
            raise ValueError("SOURCE_CHANGED_DURING_CHECKS")
        if not n06_unchanged or not n07a_unchanged:
            raise ValueError("HISTORICAL_SOURCE_RECEIPT_MISMATCH")
        receipt["source_sha256"] = after
        receipt["source_file_count"] = len(after)
        receipt["collector_state"] = "COMPLETED"
        receipt["result"] = "PASS"
        receipt["active_command"] = None
        checkpoint()
        index = output_index(receipt_path, receipt)
        print(json.dumps({
            "result": receipt["result"],
            "receipt": receipt_path.relative_to(ROOT).as_posix(),
            "receipt_sha256": sha256_file(receipt_path),
            "outputs_index": index.relative_to(ROOT).as_posix(),
            "outputs_index_sha256": sha256_file(index),
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
        if not index_path.exists():
            output_index(receipt_path, receipt)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--offline-python",
        type=Path,
        default=BACKEND / "artifacts" / "repro-env" / "Scripts" / "python.exe",
    )
    try:
        return collect(parser.parse_args())
    except (OSError, ValueError, FileNotFoundError, RuntimeError, subprocess.SubprocessError) as exc:
        print("N07B mTLS truncated-body collection FAILED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
