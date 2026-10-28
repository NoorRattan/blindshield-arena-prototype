"""Collect bounded N07 component-review evidence; never full probe acceptance."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

from verify_n04 import sources


ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path, value):
    pending = path.with_suffix(path.suffix + ".pending")
    with pending.open("wb") as stream:
        stream.write((json.dumps(value, indent=2) + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, path)


def collect(args):
    output = args.output.resolve()
    if output.exists() or not output.is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_IGNORED_RECEIPT_REQUIRED")
    runtime_args = (args.cell_lock, args.model, args.corpus, args.corpus_receipt, args.corpus_keys)
    if any(runtime_args) and not all(runtime_args):
        raise ValueError("ALL_REAL_RUNTIME_INPUTS_REQUIRED")
    work = ROOT / "artifacts/n07-review-checks" / uuid4().hex
    work.mkdir(parents=True)
    before = sources()
    n06_path = ROOT.parent / "memory files/hackathon/evidence/n06-completion-verification-2026-10-22.json"
    n06 = json.loads(n06_path.read_bytes())
    n06_unchanged = all(before.get(path) == value for path, value in n06["source_sha256"].items())
    receipt = dict(
        schema_version="arena-n07-reviewed-components.v1",
        observed_at_utc=datetime.now(timezone.utc).isoformat(),
        reviewed_base_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip(),
        scope="N07_REVIEWED_COMPONENTS_AND_EXPLICIT_RESTORE_REFUSAL_NOT_FULL_PROBE_ACCEPTANCE",
        result="FAIL", collector_state="IN_PROGRESS", active_command=None,
        source_sha256=before, source_unchanged_during_checks=False,
        original_n06_sources_unchanged=n06_unchanged,
        original_n06_receipt_sha256=sha(n06_path),
        command_results=[], real_model_regression_requested=bool(all(runtime_args)),
        real_model_regression=None, automatic_resume_implemented=False,
        independent_rollback_anchor_implemented=False, full_n07_acceptance=False,
        full_arena_acceptance=False, guarantee_tier_achieved=None,
        frontend_changed=False, hosted_model_api_used=False,
    )

    def checkpoint():
        atomic_json(output, receipt)
        atomic_json(work / "progress.json", receipt)

    def execute(name, command, timeout=1800):
        receipt["active_command"] = name
        checkpoint()
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as exc:
            code, raw = 124, (exc.stdout or b"") + (exc.stderr or b"") + b"\nCOMMAND_TIMEOUT\n"
        path = work / (name + ".log")
        with path.open("wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        lines = raw.decode(errors="replace").strip().splitlines()
        item = dict(name=name, command=command, exit_code=code,
                    raw_output=path.relative_to(ROOT.parent).as_posix(), raw_sha256=sha(path),
                    summary=lines[-1] if lines else "")
        receipt["command_results"].append(item)
        receipt["active_command"] = None
        checkpoint()
        print(json.dumps({key: item[key] for key in ("name", "exit_code", "summary")}), flush=True)
        if code:
            raise ValueError("REQUIRED_COMMAND_FAILED")

    checkpoint()
    try:
        focused = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "tests/integration").glob("test_n07_*.py"))
        if len(focused) < 6 or not n06_unchanged:
            raise ValueError("REVIEWED_COMPONENT_SOURCES_REQUIRED")
        execute("n07-components", [sys.executable, "-m", "pytest", "-q", "-W", "error", *focused])
        execute("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"])
        execute("pytest-offline", [str(args.offline_python.resolve()), "-m", "pytest", "-q", "-W", "error"])
        for name, command in (
            ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
            ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
            ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
            ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
            ("dependencies", [sys.executable, "-m", "pip", "check"]),
        ):
            execute(name, command)
        if all(runtime_args):
            admission = work / "admission"
            execute("prepare-three-lane-regression", [sys.executable, "tools/prepare_n05.py", "--cell-lock", str(args.cell_lock.resolve()), "--output", str(admission)])
            directory = work / "real-three-lane"
            execute("real-three-lane-regression", [sys.executable, "-m", "arena.integration.cli",
                    "--lock", str(admission / "admission.json"), "--model", str(args.model.resolve()),
                    "--corpus", str(args.corpus.resolve()), "--corpus-receipt", str(args.corpus_receipt.resolve()),
                    "--corpus-keys", str(args.corpus_keys.resolve()), "--output", str(directory),
                    "--traffic", "real", "--mode", "INPUT", "--lanes", "3"], timeout=1800)
            summary_path = directory / "summary.json"
            summary = json.loads(summary_path.read_bytes())
            if not (summary["real_model"] and summary["run_label"] == "REAL_PUBLIC" and summary["lane_count"] == 3
                    and summary["turns"] == summary["model_dispatches"] == 6 and summary["turn_replay_no_redispatch"]
                    and summary["verifier_exit_code"] == 0
                    and summary["verifier_result"]["diagnostics"]["turn_openings_verified"] == 6
                    and all(row["model_execution"] == "EXECUTED" and row["integrity"] == "VALID_WITHIN_PROFILE" for row in summary["results"])):
                raise ValueError("REAL_FUNCTIONAL_REGRESSION_REQUIRED")
            receipt["real_model_regression"] = dict(
                path=summary_path.relative_to(ROOT.parent).as_posix(), sha256=sha(summary_path),
                real_model=True, run_label="REAL_PUBLIC", turns=6, model_dispatches=6, lane_count=3,
                private_openings_verified=6, turn_replay_no_redispatch=True,
                safety_scoring_validated=False, full_cache_or_probe_acceptance=False,
            )
        counts = [int(match.group(1)) for item in receipt["command_results"] if item["name"].startswith("pytest-")
                  for match in [re.search(r"(\d+) passed", item["summary"])] if match]
        skipped = [int(match.group(1)) if match else 0 for item in receipt["command_results"] if item["name"].startswith("pytest-")
                   for match in [re.search(r"(\d+) skipped", item["summary"])]]
        unchanged = before == sources()
        ok = len(counts) == 2 and counts[0] == counts[1] and counts[0] >= 361 and unchanged
        receipt.update(result="PASS" if ok else "FAIL", collector_state="COMPLETED", active_command=None,
                       observed_at_utc=datetime.now(timezone.utc).isoformat(), pytest_counts=counts,
                       source_unchanged_during_checks=unchanged, pytest_skipped_counts=skipped)
        checkpoint()
        print(json.dumps({key: receipt[key] for key in ("result", "collector_state", "pytest_counts", "full_n07_acceptance")}), flush=True)
        return 0 if ok else 1
    except Exception as exc:
        receipt.update(result="FAIL", collector_state="FAILED", error_type=type(exc).__name__)
        checkpoint()
        print(json.dumps({"result": "FAIL", "error_type": type(exc).__name__}), flush=True)
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline-python", type=Path, required=True)
    for name in ("cell-lock", "model", "corpus", "corpus-receipt", "corpus-keys"):
        parser.add_argument("--" + name, type=Path)
    return collect(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
