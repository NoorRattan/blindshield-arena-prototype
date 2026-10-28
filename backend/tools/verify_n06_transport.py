"""Retain exact source-bound local mTLS, real model, regression and suite evidence.

No calibrated public policy, statistical latency/channel or full N06 acceptance.
Private keys, prompts, model weights and replay bundles stay in ignored artifacts.
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
from arena.execution.transport import ExecutionEnvelope, LabProfile, SignedLabProfile
from verify_n04 import sources
from verify_n06_worker import check_database


ROOT = Path(__file__).resolve().parents[1]


def check_transport(workspace, summary):
    durable = check_database(workspace, summary)
    if (summary["schema_version"] != "arena-n06-local-mtls-run.v1" or not summary["local_participant_transport"]
        or not summary["service_quiesced"] or not summary["network_timing_measured"]
        or summary["public_execution_available"] or summary["calibrated_public_policy"]):
        raise ValueError("REAL_LOCAL_MTLS_SCOPE_REQUIRED")
    with sqlite3.connect(workspace / "broker.sqlite3") as conn:
        conn.row_factory = sqlite3.Row
        owner = conn.execute("SELECT * FROM n06_lab_runs").fetchone()
        if owner["state"] != "QUIESCED" or json.loads(owner["profile_json"])["profile"] != summary["local_transport_profile"]:
            raise ValueError("REAL_LOCAL_MTLS_QUIESCED_OWNER_REQUIRED")
        rows = list(conn.execute("SELECT t.turn_index,s.lane,j.admitted_ns FROM n06_jobs j JOIN turns t ON t.id=j.turn_id JOIN sessions s ON s.id=j.session_id ORDER BY t.turn_index,s.lane"))
        for begin in (0, 3):
            times = [row["admitted_ns"] for row in rows[begin:begin+3]]
            if max(times) - min(times) >= summary["local_transport_profile"]["admission_window_ms"] * 1_000_000:
                raise ValueError("THREE_REAL_SUBMISSIONS_MISSED_FIXED_WINDOW")
    network = summary["network_samples"]
    if len(network) != 6 or {r["sample_index"] for r in network} != set(range(6)):
        raise ValueError("SIX_NETWORK_SAMPLES_REQUIRED")
    for row in network:
        if not 0 < row["admission_rtt_ns"] < 5_000_000_000 or not 0 < row["final_poll_rtt_ns"] < 5_000_000_000:
            raise ValueError("BOUNDED_LOCAL_HTTP_REQUEST_REQUIRED")
        if any(row[k] != summary["feedback_policy"]["body_bytes"] for k in ("ack_bytes", "pending_bytes", "feedback_bytes")):
            raise ValueError("FIXED_HTTP_BYTES_REQUIRED")
    return durable | {"local_mtls_turns": 6, "rounds": 2, "owner_state": "QUIESCED", "new_public_admission": False,
        "maximum_admission_rtt_ns": max(r["admission_rtt_ns"] for r in network),
        "maximum_final_poll_rtt_ns": max(r["final_poll_rtt_ns"] for r in network)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cell-lock", "model", "corpus", "corpus-receipt", "corpus-keys", "offline-python", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_VERIFICATION_RECEIPT_REQUIRED")
    before = sources()
    work = ROOT / "artifacts/n06-transport-checks" / uuid4().hex
    work.mkdir(parents=True)
    lock = work / "admission/admission.json"
    preparation, real = work / "policy", work / "real-mtls"
    common = ["--lock", str(lock), "--model", str(args.model.resolve()), "--corpus", str(args.corpus.resolve()),
        "--corpus-receipt", str(args.corpus_receipt.resolve()), "--corpus-keys", str(args.corpus_keys.resolve())]
    results = []
    def execute(name, command, timeout=600):
        try:
            ran = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=timeout)
            code, raw = ran.returncode, ran.stdout + ran.stderr
        except subprocess.TimeoutExpired as exc:
            code, raw = 124, (exc.stdout or b"") + (exc.stderr or b"") + b"\nCOMMAND_TIMEOUT\n"
        path = work / (name + ".log")
        path.write_bytes(raw)
        lines = raw.decode(errors="replace").strip().splitlines()
        summary = lines[-1] if lines else ""
        if name.startswith("real-"): summary = "REAL_RUN_PASS" if code == 0 else "REAL_RUN_FAILED"
        item = {"name": name, "command": command, "exit_code": code, "raw_output": path.relative_to(ROOT.parent).as_posix(),
            "raw_sha256": sha256(raw), "summary": summary}
        results.append(item)
        print(json.dumps({k: item[k] for k in ("name", "exit_code", "summary")}), flush=True)
        return code
    if not execute("prepare-three-lanes", [sys.executable, "tools/prepare_n05.py", "--cell-lock", str(args.cell_lock.resolve()), "--output", str(lock.parent)]):
        if not execute("prepare-fixed-policy", [sys.executable, "tools/prepare_n06_pilot.py", "--execution-lock", str(lock), "--output", str(preparation)]):
            execute("real-mtls-six-turns", [sys.executable, "-m", "arena.integration.cli", *common, "--output", str(real), "--mode", "INPUT",
                "--traffic", "real", "--lanes", "3", "--n06-policy", str(preparation / "policy.json"),
                "--n06-policy-public-key", str(preparation / "policy-public.hex"), "--n06-policy-key-id", "n06-local-policy", "--n06-local-mtls"])
    for name, command in (
        ("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"]),
        ("pytest-offline", [str(args.offline_python.resolve()), "-m", "pytest", "-q", "-W", "error"]),
        ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
        ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
        ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
        ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
        ("dependencies", [sys.executable, "-m", "pip", "check"]),
    ):
        execute(name, command)
    if lock.exists():
        execute("real-single-lane-regression", [sys.executable, "-m", "arena.integration.cli",
            *[str(lock.parent / "cell-admission.json") if value == str(lock) else value for value in common],
            "--output", str(work / "single-lane"), "--traffic", "real", "--mode", "INPUT"])
    after = sources()
    summary = json.loads((real / "summary.json").read_bytes()) if (real / "summary.json").exists() else None
    error, durable = None, None
    try:
        if summary is None: raise ValueError("REAL_LOCAL_MTLS_RUN_REQUIRED")
        durable = check_transport(real, summary)
        schema = {name: model.model_json_schema() for name, model in (("ExecutionEnvelope", ExecutionEnvelope), ("LabProfile", LabProfile), ("SignedLabProfile", SignedLabProfile))}
        if json.loads((ROOT / "contracts/n06-local-mtls.schema.json").read_bytes()) != schema:
            raise ValueError("LOCAL_TRANSPORT_SCHEMA_MISMATCH")
    except (KeyError, ValueError, TypeError) as exc:
        error = type(exc).__name__
    counts = [int(m.group(1)) for item in results if item["name"].startswith("pytest")
        for m in [re.search(r"(\d+) passed", item["summary"])] if m]
    receipt = {"schema_version": "arena-n06b2-transport-verification.v1", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewed_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "N06B2_LOOPBACK_MTLS_AND_FAILURE_COMPONENTS_NOT_CALIBRATED_PUBLIC_ADMISSION",
        "result": "PASS" if not error and before == after and all(item["exit_code"] == 0 for item in results) and len(counts) == 2 else "FAIL",
        "validation_error_type": error, "source_sha256": before, "source_unchanged_during_checks": before == after,
        "python_version": sys.version.split()[0], "pytest_counts": counts, "command_results": results,
        "real_mtls": summary, "durable_transport_checks": durable,
        "local_participant_transport": bool(durable), "network_timing_measured": bool(durable),
        "public_execution_available": False, "calibrated_public_policy": False, "timing_auc_measured": False,
        "full_n06_complete": False, "full_arena_acceptance": False, "guarantee_tier_achieved": None,
        "frontend_changed": False, "global_ml_packages_changed": False, "hosted_model_api_used": False}
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"result": receipt["result"], "pytest_counts": counts, "validation_error_type": error, "local_participant_transport": bool(durable)}))
    return 0 if receipt["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
