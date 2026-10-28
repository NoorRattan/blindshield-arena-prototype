"""Retain exact local component commands/results. Never an arena acceptance runner."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import sys
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = ROOT.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="Fresh receipt path under ignored artifacts/")
    parser.add_argument("--offline-python", type=Path, help="Optional existing offline-installed environment")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts") or output.exists():
        raise ValueError("Receipt must be new and under artifacts")
    raw_dir = ROOT / "artifacts" / "broker-checks" / uuid4().hex
    raw_dir.mkdir(parents=True)
    commands = [[sys.executable, "-m", "pytest", "-q", "-W", "error"]]
    if args.offline_python:
        commands.append([str(args.offline_python.resolve()), "-m", "pytest", "-q", "-W", "error"])
    commands.extend([
        [sys.executable, "examples/broker_control_smoke.py"],
        [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"],
        [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"],
        [sys.executable, "examples/monu_contract_smoke.py"],
        [sys.executable, "-m", "pip", "check"],
    ])
    results = []
    for index, argv in enumerate(commands):
        try:
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=180)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            code, raw = 124, b"COMPONENT_COMMAND_TIMEOUT\n"
        path = raw_dir / f"{index + 1:02}.txt"
        path.write_bytes(raw)
        safe_command = [Path(word).resolve().relative_to(ROOT).as_posix() if Path(word).is_absolute() and Path(word).resolve().is_relative_to(ROOT) else word for word in argv]
        summary = raw.decode("utf-8", errors="replace").strip().splitlines()[-1:]
        results.append({"command": safe_command, "exit_code": code, "raw_output": path.relative_to(ROOT).as_posix(),
                        "raw_sha256": digest(path), "summary": summary[0] if summary else ""})
        print(json.dumps({"command": safe_command, "exit_code": code, "summary": summary}), flush=True)
    paths = sorted(set(
        list((ROOT / "src/arena").rglob("*.py")) + list((ROOT / "tests").rglob("*.py")) +
        list((ROOT / "infra").rglob("*.py")) + list((ROOT / "infra").rglob("*.json")) +
        list((ROOT / "config").glob("*.json")) + list((ROOT / "contracts").glob("*.json")) +
        list((ROOT / "fixtures").rglob("*.json")) + list((ROOT / "examples").glob("*.py")) +
        list((ROOT / "tools").glob("*.py")) + [ROOT / "pyproject.toml", ROOT / "requirements.lock"]
    ))
    counts = [int(match.group(1)) for result in results if "pytest" in result["command"]
              for match in [re.search(r"(\d+) passed", result["summary"])] if match]
    receipt = {"schema": "arena-broker-component-tests.v1", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
               "scope": "N03 real local mTLS/SQLite/CLI and synthetic reservations/crash fixtures only; no inference, recorder/witness, shaping, deployed sandbox or arena T/P acceptance",
               "result": "PASS" if all(r["exit_code"] == 0 for r in results) else "FAIL",
               "pytest_counts": counts, "broker_test_count": 25,
               "runtime": {"python": sys.version.split()[0], "sqlite": sqlite3.sqlite_version, "openssl": ssl.OPENSSL_VERSION,
                           "platform": sys.platform, "sqlite_policy": "WAL, synchronous=FULL, foreign_keys=ON, BEGIN IMMEDIATE"},
               "working_directory": "backend", "source_paths_relative_to": "repository root",
               "command_results": results, "source_sha256": {p.relative_to(REPOSITORY).as_posix(): digest(p) for p in paths},
               "limitations": ["RUNNING/dispatch states in reservation/recovery tests are explicitly synthetic SQL fixtures",
                               "Abrupt exit on Windows local storage is not power-loss, malicious host or rollback authority proof",
                               "No automatic external dispatch exists; missing prerequisites return POLICY_NOT_READY",
                               "No complete arena T/P test promoted; original N01 failures retained"]}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
    return 0 if receipt["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
