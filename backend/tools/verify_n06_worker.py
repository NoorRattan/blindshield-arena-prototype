"""Source-bound real worker pilot, frozen estimate and separate validation repeat.

No public HTTP activation, held-out statistical test, p99, AUC or full N06 claim.
All local keys/corpus/weights remain in ignored preparation/output paths.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from uuid import uuid4

from arena.contracts.crypto import sha256
from arena.execution.pilot import WorkerSample, candidate_from_pilot
from arena.execution.policy import FeedbackPolicy
from verify_n04 import sources


ROOT = Path(__file__).resolve().parents[1]


def check_database(workspace, summary):
    """Compare observed clocks/state to actual durable rows, not summary flags alone."""
    with sqlite3.connect(workspace / "broker.sqlite3") as conn:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute("SELECT j.*,s.lane,t.turn_index FROM n06_jobs j JOIN sessions s ON s.id=j.session_id JOIN turns t ON t.id=j.turn_id ORDER BY t.turn_index,s.lane"))
        if len(rows) != 6 or conn.execute("SELECT admitted FROM budgets").fetchone()[0] != 6:
            raise ValueError("REAL_WORKER_DURABLE_BUDGET_MISMATCH")
        if tuple(conn.execute("SELECT phase,integrity FROM experiments").fetchone()) != ("RELEASED", "VALID_WITHIN_PROFILE"):
            raise ValueError("REAL_WORKER_AUTHORITATIVE_RELEASE_REQUIRED")
        if conn.execute("SELECT count(*) FROM n04_turns WHERE state='DONE' AND known_execution='EXECUTED'").fetchone()[0] != 6:
            raise ValueError("REAL_WORKER_SIX_COMPLETIONS_REQUIRED")
        for row, raw in zip(rows, summary["worker_samples"], strict=True):
            sample = WorkerSample.model_validate(raw)
            if (sample.sample_index != row["turn_index"] * 3 + row["lane"] or sample.lane != row["lane"]
                or any(getattr(sample, key) != row[key] for key in ("admitted_ns", "deadline_ns", "release_ns"))
                or row["state"] != "AUTHORIZED" or row["published"] != 1 or not row["body_ref"]):
                raise ValueError("REAL_WORKER_SAMPLE_DURABLE_ROW_MISMATCH")
    if (summary["turns"] != 6 or summary["model_dispatches"] != 6 or summary["verifier_exit_code"] != 0
        or summary["verifier_result"]["diagnostics"]["turn_openings_verified"] != 6):
        raise ValueError("REAL_WORKER_INDEPENDENT_OPENINGS_REQUIRED")
    return {"jobs": 6, "charged_queries": 6, "published_authorized": 6, "executed": 6,
            "phase": "RELEASED", "private_openings_independently_verified": 6}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cell-lock", "model", "corpus", "corpus-receipt", "corpus-keys", "offline-python", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_RECEIPT_REQUIRED")
    before = sources()
    directory = ROOT / "artifacts/n06-worker-checks" / uuid4().hex
    directory.mkdir(parents=True)
    lock = directory / "admission/admission.json"
    pilot, validation = directory / "pilot", directory / "validation"
    bootstrap, candidate = directory / "bootstrap", directory / "candidate"
    common = ["--lock", str(lock), "--model", str(args.model.resolve()), "--corpus", str(args.corpus.resolve()),
              "--corpus-receipt", str(args.corpus_receipt.resolve()), "--corpus-keys", str(args.corpus_keys.resolve())]
    def run_command(name, command, timeout=600):
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            code, raw = 124, (error.stdout or b"") + (error.stderr or b"") + b"\nCOMMAND_TIMEOUT\n"
        log = directory / (name + ".log")
        log.write_bytes(raw)
        lines = raw.decode(errors="replace").strip().splitlines()
        summary = lines[-1] if lines else ""
        if name in {"real-worker-pilot", "real-worker-validation", "single-lane-regression"}:
            summary = "REAL_RUN_PASS" if code == 0 else "REAL_RUN_FAILED"
        record = {"name": name, "command": command, "exit_code": code, "raw_output": log.relative_to(ROOT.parent).as_posix(),
                  "raw_sha256": sha256(raw), "summary": summary}
        print(json.dumps({k: record[k] for k in ("name", "exit_code", "summary")}), flush=True)
        return record
    results = []
    setup = [("prepare-three-lanes", [sys.executable, "tools/prepare_n05.py", "--cell-lock", str(args.cell_lock.resolve()), "--output", str(lock.parent)]),
             ("prepare-bootstrap", [sys.executable, "tools/prepare_n06_pilot.py", "--execution-lock", str(lock), "--output", str(bootstrap)])]
    for name, command in setup:
        results.append(run_command(name, command))
        if results[-1]["exit_code"]: break
    for name, work, preparation in (("real-worker-pilot", pilot, bootstrap), ("real-worker-validation", validation, candidate)):
        if any(r["exit_code"] for r in results): break
        if name == "real-worker-validation":
            results.append(run_command("prepare-candidate", [sys.executable, "tools/prepare_n06_pilot.py", "--execution-lock", str(lock),
                "--pilot-summary", str(pilot / "summary.json"), "--output", str(candidate)]))
            if results[-1]["exit_code"]: break
        command = [sys.executable, "-m", "arena.integration.cli", *common, "--output", str(work), "--traffic", "real", "--mode", "INPUT", "--lanes", "3",
            "--n06-policy", str(preparation / "policy.json"), "--n06-policy-public-key", str(preparation / "policy-public.hex"), "--n06-policy-key-id", "n06-local-policy"]
        results.append(run_command(name, command))
    # Keep regression evidence even when the pilot fails. Never call a failed run PASS.
    checks = [("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"]),
              ("pytest-offline", [str(args.offline_python.resolve()), "-m", "pytest", "-q", "-W", "error"]),
              ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
              ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
              ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
              ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
              ("dependencies", [sys.executable, "-m", "pip", "check"])]
    for name, command in checks:
        results.append(run_command(name, command))
    if lock.exists():
        # Same pinned base cells, existing single-lane controller path.
        results.append(run_command("single-lane-regression", [sys.executable, "-m", "arena.integration.cli",
            *[str(lock.parent / "cell-admission.json") if v == str(lock) else v for v in common],
            "--output", str(directory / "single-lane"), "--traffic", "real", "--mode", "INPUT"]))
    after = sources()
    pilot_summary = json.loads((pilot / "summary.json").read_bytes()) if (pilot / "summary.json").exists() else None
    validation_summary = json.loads((validation / "summary.json").read_bytes()) if (validation / "summary.json").exists() else None
    durable = {}
    error = None
    try:
        if not pilot_summary or not validation_summary:
            raise ValueError("PILOT_AND_VALIDATION_SUMMARIES_REQUIRED")
        durable["pilot"] = check_database(pilot, pilot_summary)
        durable["validation"] = check_database(validation, validation_summary)
        selected, estimate = candidate_from_pilot(pilot_summary["worker_samples"], FeedbackPolicy.model_validate(pilot_summary["feedback_policy"]))
        frozen = json.loads((candidate / "preparation.json").read_bytes())
        if (selected.model_dump() != frozen["policy"] or selected.model_dump() != validation_summary["feedback_policy"]
            or frozen["pilot_summary_sha256"] != sha256((pilot / "summary.json").read_bytes())
            or frozen["policy_disclosure_id"] != validation_summary["policy_disclosure_id"]):
            raise ValueError("CANDIDATE_WAS_NOT_FROZEN_FROM_PRIOR_PILOT")
    except (ValueError, KeyError, TypeError) as exc:
        error = type(exc).__name__  # No untrusted exception text in public receipts.
    counts = [int(m.group(1)) for r in results if r["name"].startswith("pytest")
              for m in [re.search(r"(\d+) passed", r["summary"])] if m]
    receipt = {"schema_version": "arena-n06b1-worker-verification.v1", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewed_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "N06B1_REAL_LOCAL_WORKER_PILOT_AND_FIXED_CANDIDATE_REPEAT_NOT_PUBLIC_TRANSPORT",
        "result": "PASS" if not error and before == after and all(r["exit_code"] == 0 for r in results) and len(counts) == 2 else "FAIL",
        "validation_error_type": error, "source_sha256": before, "source_unchanged_during_checks": before == after,
        "python_version": sys.version.split()[0], "pytest_counts": counts, "command_results": results,
        "pilot": pilot_summary, "candidate_validation": validation_summary, "durable_state_checks": durable,
        "candidate_preparation": json.loads((candidate / "preparation.json").read_bytes()) if (candidate / "preparation.json").exists() else None,
        "n06_worker_real_model": bool(pilot_summary and validation_summary and durable),
        "public_execution_available": False, "calibrated_public_policy": False, "held_out_timing_test": False,
        "network_timing_measured": False, "timing_auc_measured": False, "full_n06_complete": False, "guarantee_tier_achieved": None,
        "frontend_changed": bool(subprocess.check_output(["git", "diff", "--name-only", "HEAD", "--", "frontend"], cwd=ROOT)),
        "global_ml_packages_changed": False, "hosted_model_api_used": False}
    with args.output.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    return 0 if receipt["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
