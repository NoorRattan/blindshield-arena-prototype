"""Retain source-bound N04 local runs and component checks, never full arena acceptance."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from uuid import uuid4


ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    files = (
        set((ROOT / "src/arena").rglob("*.py"))
        | set((ROOT / "tests").rglob("*.py"))
        | set((ROOT / "tools").glob("*.py"))
    )
    for folder in ("infra", "config", "contracts", "fixtures", "examples"):
        files.update(
            path
            for path in (ROOT / folder).rglob("*")
            if path.is_file() and path.suffix in {".py", ".json", ".defense"}
        )
    files.update([ROOT / "pyproject.toml", ROOT / "requirements.lock"])
    return {
        path.relative_to(ROOT.parent).as_posix(): digest(path) for path in sorted(files)
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "model", "corpus", "corpus-receipt", "corpus-keys", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--offline-python", type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_IGNORED_RECEIPT_REQUIRED")
    before = sources()
    directory = ROOT / "artifacts/n04-checks" / uuid4().hex
    directory.mkdir(parents=True)
    commands = [
        ("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"])
    ]
    if args.offline_python:
        commands.append(
            (
                "pytest-offline",
                [
                    str(args.offline_python.resolve()),
                    "-m",
                    "pytest",
                    "-q",
                    "-W",
                    "error",
                ],
            )
        )
    commands.extend(
        [
            (
                "schemas",
                [
                    sys.executable,
                    "-m",
                    "arena.cli.main",
                    "schemas",
                    "--output",
                    "contracts/arena.v2.schema.json",
                    "--check",
                ],
            ),
            (
                "vectors",
                [
                    sys.executable,
                    "-m",
                    "arena.cli.main",
                    "check-vectors",
                    "--path",
                    "fixtures/arena-v2/vectors.json",
                ],
            ),
            ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
            ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
            ("dependencies", [sys.executable, "-m", "pip", "check"]),
        ]
    )
    run_paths = {}
    for name, mode, traffic in (
        ("real-input", "INPUT", "real"),
        ("input-controls", "INPUT", "synthetic"),
        ("output-control", "OUTPUT", "synthetic"),
        ("real-features", "FEATURES", "real"),
        ("post-hoc-controls", "POST_HOC", "synthetic"),
    ):
        run_path = directory / name
        run_paths[name] = run_path
        command = [
            sys.executable,
            "-m",
            "arena.integration.cli",
            "--lock",
            str(args.lock.resolve()),
            "--model",
            str(args.model.resolve()),
            "--corpus",
            str(args.corpus.resolve()),
            "--corpus-receipt",
            str(args.corpus_receipt.resolve()),
            "--corpus-keys",
            str(args.corpus_keys.resolve()),
            "--output",
            str(run_path),
            "--mode",
            mode,
            "--traffic",
            traffic,
        ]
        commands.append((name, command))
    results = []
    for name, command in commands:
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=240)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as exc:
            code, raw = (
                124,
                (exc.stdout or b"") + (exc.stderr or b"") + b"\nCOMMAND_TIMEOUT\n",
            )
        log = directory / (name + ".log")
        log.write_bytes(raw)
        safe = []
        for value in command:
            path = Path(value)
            safe.append(
                path.resolve().relative_to(ROOT.parent).as_posix()
                if path.is_absolute() and path.resolve().is_relative_to(ROOT.parent)
                else value
            )
        summary = raw.decode("utf-8", errors="replace").strip().splitlines()[-1:]
        if name in run_paths:
            summary = (
                ["Local single-lane run complete; inspect bounded summary.json"]
                if code == 0
                else ["LOCAL_RUN_FAILED_OR_INCONCLUSIVE"]
            )
        results.append(
            {
                "name": name,
                "command": safe,
                "exit_code": code,
                "raw_output": log.relative_to(ROOT.parent).as_posix(),
                "raw_sha256": digest(log),
                "summary": summary[0] if summary else "",
            }
        )
        print(
            json.dumps({"name": name, "exit_code": code, "summary": summary}),
            flush=True,
        )
    after = sources()
    runs = {}
    for name, path in run_paths.items():
        if (path / "summary.json").is_file():
            runs[name] = {
                "summary": json.loads((path / "summary.json").read_bytes()),
                "summary_sha256": digest(path / "summary.json"),
                "public_bundle_sha256": digest(path / "public-evidence.zip"),
                "verifier_log_sha256": digest(path / "verifier.stdout.json"),
            }
    counts = [
        int(match.group(1))
        for item in results
        if item["name"].startswith("pytest")
        for match in [re.search(r"(\d+) passed", item["summary"])]
        if match
    ]
    receipt = {
        "schema_version": "arena-n04-local-verification.v1",
        "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewed_base_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "scope": "N04_LOCAL_SINGLE_LANE_COMPONENT_INTEGRATION_NOT_FULL_ARENA_ACCEPTANCE",
        "result": "PASS"
        if before == after
        and len(runs) == 5
        and all(item["exit_code"] == 0 for item in results)
        else "FAIL",
        "source_unchanged_during_checks": before == after,
        "source_sha256": before,
        "pytest_counts": counts,
        "python_version": sys.version.split()[0],
        "sqlite_version": sqlite3.sqlite_version,
        "working_directory": "backend",
        "command_results": results,
        "runs": runs,
        "execution_lock_sha256": digest(args.lock),
        "frontend_changed": False,
        "global_ml_packages_changed": False,
        "hosted_model_api_used": False,
        "post_hoc_implemented": True,
        "n04_single_lane_functional_milestone": True,
        "n04_complete": False,
        "n05_three_lane_acceptance": False,
        "n06_shaping_acceptance": False,
        "full_arena_acceptance": False,
        "safety_scoring": "UNCERTAIN_UNVALIDATED_MARKER_OBSERVATION",
        "limitations": [
            "Trusted local Docker administrator and library witness; not separately deployed hostile service proof",
            "No complete T/P acceptance, private-data activation, whole-system side-channel bound or Windows ACL assurance",
            "POST_HOC is a separately linked observation, not prevention; comprehensive start/turn crash recovery remains N07 work",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    return 0 if receipt["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
