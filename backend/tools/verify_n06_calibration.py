"""N06C exact-build sealed profiles, held-out workload and synthetic timing evidence.

Keep every attempt and raw output. A component PASS never promotes p99, real
model AUC, public admission, complete recovery, full N06 or whole-arena acceptance.
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
from arena.contracts.transport_profile import SealedTransportPlan, SealIntent
from arena.execution.calibration import select_workload_policy, zero_failure_upper_bound
from arena.execution.pilot import WorkerSample
from arena.execution.policy import FeedbackPolicy
from verify_n04 import sources

ROOT = Path(__file__).resolve().parents[1]


def check_run(path, run):
    if (run["schema_version"] != "arena-n06-sealed-run.v1" or not run["sealed_transport_profile"]
        or not run["transport_profile_independently_verified"] or not run["service_quiesced"]
        or run["verifier_exit_code"] != 0 or run["turns"] != 24
        or run["verifier_result"]["diagnostics"]["turn_openings_verified"] != 24
        or not run["verifier_result"]["diagnostics"]["transport_profile_verified"]
        or run["public_execution_available"] or run["calibrated_public_policy"] or run["timing_application_attested"]):
        raise ValueError("EXACT_SEALED_WORKLOAD_REQUIRED")
    samples = [WorkerSample.model_validate(raw) for raw in run["worker_samples"]]
    if sorted(s.sample_index for s in samples) != list(range(24)): raise ValueError("ALL_WORKLOAD_SAMPLES_REQUIRED")
    with sqlite3.connect(path / "broker.sqlite3") as conn:
        conn.row_factory = sqlite3.Row
        rows = list(conn.execute("SELECT j.*,s.lane,t.turn_index FROM n06_jobs j JOIN sessions s ON s.id=j.session_id JOIN turns t ON t.id=j.turn_id ORDER BY t.turn_index,s.lane"))
        if (len(rows) != 24 or conn.execute("SELECT admitted FROM budgets").fetchone()[0] != 24
            or tuple(conn.execute("SELECT phase,integrity FROM experiments").fetchone()) != ("RELEASED","VALID_WITHIN_PROFILE")
            or conn.execute("SELECT count(*) FROM n04_turns WHERE state='DONE' AND known_execution='EXECUTED'").fetchone()[0] != 24
            or conn.execute("SELECT state FROM n06_lab_runs").fetchone()[0] != "QUIESCED"):
            raise ValueError("AUTHORITATIVE_24_TURN_CLOSE_REQUIRED")
        for row, sample in zip(rows, samples, strict=True):
            if (sample.sample_index != row["turn_index"]*3+row["lane"] or sample.lane != row["lane"]
                or any(getattr(sample,key)!=row[key] for key in ("admitted_ns","deadline_ns","release_ns"))
                or row["state"] != "AUTHORIZED" or row["published"] != 1 or not row["body_ref"]):
                raise ValueError("DURABLE_SAMPLE_MISMATCH")
        for begin in range(0,24,3):
            times = [r["admitted_ns"] for r in rows[begin:begin+3]]
            if max(times)-min(times) >= run["local_transport_profile"]["admission_window_ms"]*1_000_000:
                raise ValueError("THREE_LANE_WINDOW_MISSED")
    network = run["network_samples"]
    if sorted(r["sample_index"] for r in network) != list(range(24)): raise ValueError("ALL_NETWORK_SAMPLES_REQUIRED")
    for row in network:
        if (any(row[k]!=run["feedback_policy"]["body_bytes"] for k in ("ack_bytes","pending_bytes","feedback_bytes"))
            or not 0 < row["admission_rtt_ns"] < 5_000_000_000 or not 0 < row["final_poll_rtt_ns"] < 5_000_000_000):
            raise ValueError("NETWORK_BYTES_OR_BOUNDED_RTT_MISMATCH")
    return {"jobs":24,"charged_queries":24,"published_authorized":24,"known_executed":24,"private_openings":24,
        "sealed_profile_independently_verified":True,"rounds":8,"owner_state":"QUIESCED",
        "maximum_worker_ns":max(s.authorized_observed_ns-s.admitted_ns for s in samples),
        "maximum_admission_rtt_ns":max(r["admission_rtt_ns"] for r in network),
        "maximum_final_poll_rtt_ns":max(r["final_poll_rtt_ns"] for r in network)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cell-lock","model","corpus","corpus-receipt","corpus-keys","offline-python","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_RECEIPT_REQUIRED")
    before = sources(); work = ROOT / "artifacts/n06-calibration-checks" / uuid4().hex; work.mkdir(parents=True)
    # Freeze this finite protocol before either real split is executed.
    protocol = {"schema_version":"arena-n06-workload-protocol.v1","source_sha256":before,
        "split":"sort each admitted JBB split by UTF-8 length then stable payload_ref; first12 per split for selection; next12 for validation",
        "per_prompt_max_utf8_bytes":80,"turns_per_phase":24,"waves":8,"lanes":3,
        "selection_rule":"ceil_seconds(max + max(2s, 0.5*max)); min 5s; floor=deadline+1s; unchanged bytes",
        "failure_handling":"retain all failures; no sample filtering or candidate retuning from validation",
        "p99_certified":False,"public_admission":False}
    (work / "protocol.json").write_text(json.dumps(protocol,indent=2)+"\n",encoding="ascii")
    lock = work / "admission/admission.json"; bootstrap = work / "bootstrap"; candidate = work / "candidate"
    common = ["--lock",str(lock),"--model",str(args.model.resolve()),"--corpus",str(args.corpus.resolve()),
        "--corpus-receipt",str(args.corpus_receipt.resolve()),"--corpus-keys",str(args.corpus_keys.resolve())]
    results=[]
    def execute(name,command,timeout=1200):
        try:
            ran=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=timeout); code,raw=ran.returncode,ran.stdout+ran.stderr
        except subprocess.TimeoutExpired as exc:
            code,raw=124,(exc.stdout or b"")+(exc.stderr or b"")+b"\nCOMMAND_TIMEOUT\n"
        log=work/(name+".log");log.write_bytes(raw)
        lines=raw.decode(errors="replace").strip().splitlines(); last=lines[-1] if lines else ""
        if name.startswith("real-"): last="REAL_RUN_PASS" if code==0 else "REAL_RUN_FAILED"
        item=dict(name=name,command=command,exit_code=code,raw_output=log.relative_to(ROOT.parent).as_posix(),raw_sha256=sha256(raw),summary=last)
        results.append(item);print(json.dumps({k:item[k] for k in ("name","exit_code","summary")}),flush=True)
        return code
    if not execute("prepare-three-lanes",[sys.executable,"tools/prepare_n05.py","--cell-lock",str(args.cell_lock.resolve()),"--output",str(lock.parent)]):
        if not execute("prepare-bootstrap",[sys.executable,"tools/prepare_n06_pilot.py","--execution-lock",str(lock),"--output",str(bootstrap)]):
            for phase,policy in (("selection",bootstrap),("validation",candidate)):
                if phase=="validation" and execute("freeze-candidate",[sys.executable,"tools/prepare_n06_calibration.py","--execution-lock",str(lock),
                    "--selection-summary",str(work / "selection/summary.json"),"--output",str(candidate)]): break
                if execute("real-"+phase,[sys.executable,"-m","arena.integration.cli",*common,"--output",str(work/phase),"--mode","INPUT","--traffic","real","--lanes","3",
                    "--n06-policy",str(policy/"policy.json"),"--n06-policy-public-key",str(policy/"policy-public.hex"),"--n06-policy-key-id","n06-local-policy",
                    "--n06-local-mtls","--n06-sealed-profile","--n06-workload",phase]): break
    # Run the synthetic-only timing experiment separately from real model load.
    execute("synthetic-timing",[sys.executable,"tools/measure_n06_timing.py","--output",str(work/"timing")],timeout=1800)
    for name,command in (
        ("pytest-primary",[sys.executable,"-m","pytest","-q","-W","error"]),
        ("pytest-offline",[str(args.offline_python.resolve()),"-m","pytest","-q","-W","error"]),
        ("schemas",[sys.executable,"-m","arena.cli.main","schemas","--output","contracts/arena.v2.schema.json","--check"]),
        ("vectors",[sys.executable,"-m","arena.cli.main","check-vectors","--path","fixtures/arena-v2/vectors.json"]),
        ("control-smoke",[sys.executable,"examples/broker_control_smoke.py"]),
        ("contract-smoke",[sys.executable,"examples/monu_contract_smoke.py"]),
        ("dependencies",[sys.executable,"-m","pip","check"])): execute(name,command)
    if lock.exists(): execute("real-single-lane-regression",[sys.executable,"-m","arena.integration.cli",
        *[str(lock.parent/"cell-admission.json") if v==str(lock) else v for v in common],"--output",str(work/"single-lane"),"--traffic","real","--mode","INPUT"])
    runs={phase:json.loads((work/phase/"summary.json").read_bytes()) if (work/phase/"summary.json").exists() else None for phase in ("selection","validation")}
    durable={};error=None;estimate=None
    try:
        for phase,run in runs.items(): durable[phase]=check_run(work/phase,run)
        selected,estimate=select_workload_policy(runs["selection"]["worker_samples"],FeedbackPolicy.model_validate(runs["selection"]["feedback_policy"]))
        frozen=json.loads((candidate/"preparation.json").read_bytes())
        if (selected.model_dump()!=runs["validation"]["feedback_policy"] or selected.model_dump()!=frozen["policy"]
            or frozen["selection_summary_sha256"]!=sha256((work/"selection/summary.json").read_bytes())
            or any(len(set(run["workload_record_sha256"]))!=24 for run in runs.values())
            or set(runs["selection"]["workload_record_sha256"]) & set(runs["validation"]["workload_record_sha256"])):
            raise ValueError("DISJOINT_HELD_OUT_FROZEN_POLICY_REQUIRED")
        schema={model.__name__:model.model_json_schema() for model in (SealedTransportPlan,SealIntent)}
        if schema!=json.loads((ROOT/"contracts/n06-sealed-transport.schema.json").read_bytes()): raise ValueError("SEALED_SCHEMA_MISMATCH")
    except (ValueError,KeyError,TypeError) as exc: error=type(exc).__name__
    timing=json.loads((work/"timing/analysis.json").read_bytes()) if (work/"timing/analysis.json").exists() else None
    counts=[int(m.group(1)) for r in results if r["name"].startswith("pytest") for m in [re.search(r"(\d+) passed",r["summary"])] if m]
    after=sources()
    receipt=dict(schema_version="arena-n06c-calibration-verification.v1",observed_at_utc=datetime.now(timezone.utc).isoformat(),
        reviewed_base_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        scope="N06C_SEALED_PROFILES_FINITE_REAL_WORKLOAD_AND_SYNTHETIC_TIMING_NOT_PUBLIC_SECURITY_ACCEPTANCE",
        result="PASS" if not error and timing is not None and before==after and all(r["exit_code"]==0 for r in results) and len(counts)==2 else "FAIL",
        validation_error_type=error,source_sha256=before,source_unchanged_during_checks=before==after,
        python_version=sys.version.split()[0],pytest_counts=counts,command_results=results,
        selection=runs["selection"],validation=runs["validation"],durable_checks=durable,selection_estimate=estimate,timing_analysis=timing,
        workload_protocol_sha256=sha256((work/"protocol.json").read_bytes()),
        iid_zero_failure_upper_95_if_assumptions_hold=zero_failure_upper_bound(24),iid_assumption_established=False,
        public_execution_available=False,calibrated_public_policy=False,p99_certified=False,real_model_timing_auc_measured=False,
        timing_application_attested=False,full_n06_complete=False,full_arena_acceptance=False,guarantee_tier_achieved=None,
        frontend_changed=bool(subprocess.check_output(["git","diff","--name-only","HEAD","--","frontend"],cwd=ROOT)),global_ml_packages_changed=False,hosted_model_api_used=False)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n",encoding="ascii")
    print(json.dumps({"result":receipt["result"],"pytest_counts":counts,"validation_error_type":error,"timing_result":timing["result"] if timing else None}))
    return 0 if receipt["result"]=="PASS" else 1


if __name__=="__main__":raise SystemExit(main())
