"""Exact-build acceptance for the declared N06 local hackathon profile.

General deployment, universal p99/channel claims, N07 recovery and full arena
acceptance are explicitly outside this receipt. All prior failed runs remain.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from uuid import uuid4

from arena.contracts.crypto import sha256
from arena.execution.calibration import select_workload_policy
from arena.execution.policy import FeedbackPolicy
from verify_n04 import sources
from verify_n06_calibration import check_run

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("cell-lock","model","corpus","corpus-receipt","corpus-keys","offline-python","output"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT/"artifacts"):
        raise ValueError("NEW_PRIVATE_RECEIPT_REQUIRED")
    before=sources()
    work=ROOT/"artifacts/n06-completion-checks"/uuid4().hex;work.mkdir(parents=True)
    (work/"source-before.json").write_text(json.dumps(before,indent=2)+"\n",encoding="ascii",newline="\n")
    lock=work/"admission/admission.json";bootstrap=work/"bootstrap";candidate=work/"candidate"
    common=["--lock",str(lock),"--model",str(args.model.resolve()),"--corpus",str(args.corpus.resolve()),
        "--corpus-receipt",str(args.corpus_receipt.resolve()),"--corpus-keys",str(args.corpus_keys.resolve())]
    results=[]
    def execute(name,command,timeout=1800):
        try:
            ran=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=timeout);code,raw=ran.returncode,ran.stdout+ran.stderr
        except subprocess.TimeoutExpired as exc:
            code,raw=124,(exc.stdout or b"")+(exc.stderr or b"")+b"\nCOMMAND_TIMEOUT\n"
        log=work/(name+".log");log.write_bytes(raw)
        lines=raw.decode(errors="replace").strip().splitlines();last=lines[-1] if lines else ""
        if name.startswith("real-"):last="REAL_RUN_PASS" if code==0 else "REAL_RUN_FAILED"
        item=dict(name=name,command=command,exit_code=code,raw_output=log.relative_to(ROOT.parent).as_posix(),raw_sha256=sha256(raw),summary=last)
        results.append(item);print(json.dumps({k:item[k] for k in ("name","exit_code","summary")}),flush=True)
        return code
    if not execute("prepare-three-lanes",[sys.executable,"tools/prepare_n05.py","--cell-lock",str(args.cell_lock.resolve()),"--output",str(lock.parent)]):
        if not execute("prepare-bootstrap",[sys.executable,"tools/prepare_n06_pilot.py","--execution-lock",str(lock),"--output",str(bootstrap)]):
            for phase,policy in (("selection",bootstrap),("validation",candidate)):
                if phase=="validation" and execute("freeze-candidate",[sys.executable,"tools/prepare_n06_calibration.py","--execution-lock",str(lock),
                    "--selection-summary",str(work/"selection/summary.json"),"--output",str(candidate)]):break
                if execute("real-"+phase,[sys.executable,"-m","arena.integration.cli",*common,"--output",str(work/phase),"--mode","INPUT","--traffic","real","--lanes","3",
                    "--n06-policy",str(policy/"policy.json"),"--n06-policy-public-key",str(policy/"policy-public.hex"),"--n06-policy-key-id","n06-local-policy",
                    "--n06-local-mtls","--n06-sealed-profile","--n06-workload",phase]):break
    execute("mock-timing-v2",[sys.executable,"tools/measure_n06_release.py","--engine","mock","--output",str(work/"mock-timing")],timeout=2400)
    if (candidate/"policy.json").exists():
        execute("real-canary-timing-v2",[sys.executable,"tools/measure_n06_release.py","--engine","real-canary","--output",str(work/"real-timing"),
            "--lock",str(lock),"--model",str(args.model.resolve()),"--policy",str(candidate/"policy.json"),
            "--policy-public-key",str(candidate/"policy-public.hex"),"--policy-key-id","n06-local-policy"],timeout=3000)
    for name,command in (
        ("pytest-primary",[sys.executable,"-m","pytest","-q","-W","error"]),
        ("pytest-offline",[str(args.offline_python.resolve()),"-m","pytest","-q","-W","error"]),
        ("schemas",[sys.executable,"-m","arena.cli.main","schemas","--output","contracts/arena.v2.schema.json","--check"]),
        ("vectors",[sys.executable,"-m","arena.cli.main","check-vectors","--path","fixtures/arena-v2/vectors.json"]),
        ("control-smoke",[sys.executable,"examples/broker_control_smoke.py"]),
        ("contract-smoke",[sys.executable,"examples/monu_contract_smoke.py"]),
        ("dependencies",[sys.executable,"-m","pip","check"])):execute(name,command)
    if lock.exists():execute("real-single-lane-regression",[sys.executable,"-m","arena.integration.cli",
        *[str(lock.parent/"cell-admission.json") if v==str(lock) else v for v in common],"--output",str(work/"single-lane"),"--traffic","real","--mode","INPUT"])
    runs={phase:json.loads((work/phase/"summary.json").read_bytes()) if (work/phase/"summary.json").exists() else None for phase in ("selection","validation")}
    durable={};error=None
    try:
        for phase,run in runs.items():durable[phase]=check_run(work/phase,run)
        selected,_=select_workload_policy(runs["selection"]["worker_samples"],FeedbackPolicy.model_validate(runs["selection"]["feedback_policy"]))
        frozen=json.loads((candidate/"preparation.json").read_bytes())
        if (selected.model_dump()!=runs["validation"]["feedback_policy"] or selected.model_dump()!=frozen["policy"]
            or frozen["selection_summary_sha256"]!=sha256((work/"selection/summary.json").read_bytes())
            or set(runs["selection"]["workload_record_sha256"]) & set(runs["validation"]["workload_record_sha256"])):
            raise ValueError("FROZEN_DISJOINT_WORKLOAD_REQUIRED")
    except (ValueError,KeyError,TypeError) as exc:error=type(exc).__name__
    timing={};authority={}
    for engine,folder in (("mock","mock-timing"),("real-canary","real-timing")):
        path=work/folder/"analysis.json"
        timing[engine]=json.loads(path.read_bytes()) if path.exists() else None
        authority[engine]=[]
        for entry in sorted((work/folder).glob("*/authority.json")):
            value=json.loads(entry.read_bytes());verify=entry.parent/"verifier.log"
            authority[engine].append(dict(path=entry.relative_to(ROOT.parent).as_posix(),sha256=sha256(entry.read_bytes()),
                verifier_output=verify.relative_to(ROOT.parent).as_posix(),verifier_sha256=sha256(verify.read_bytes()),**value))
    counts=[int(m.group(1)) for r in results if r["name"].startswith("pytest") for m in [re.search(r"(\d+) passed",r["summary"])] if m]
    after=sources()
    timing_ok=all(t and t["result"]=="WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE" and t["source_unchanged_during_checks"] for t in timing.values())
    authority_ok=(len(authority["mock"])==28 and len(authority["real-canary"])==13
        and all(a["sealed_profile_verified"] and a["blue_projection_constant"] for values in authority.values() for a in values))
    policy_matches=False
    if runs["validation"] and (work/"real-timing/protocol.json").exists():
        plan=json.loads((work/"real-timing/protocol.json").read_bytes());policy=runs["validation"]["feedback_policy"]
        policy_matches=all(plan[a]==policy[b] for a,b in (("deadline_ms","execution_deadline_ms"),("floor_ms","release_floor_ms"),("body_bytes","body_bytes")))
    ok=not error and timing_ok and authority_ok and policy_matches and before==after and len(counts)==2 and all(r["exit_code"]==0 for r in results)
    receipt=dict(schema_version="arena-n06-local-profile-acceptance.v1",observed_at_utc=datetime.now(timezone.utc).isoformat(),
        reviewed_base_commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip(),
        scope="N06_DECLARED_LOCAL_HACKATHON_PROFILE_NOT_GENERAL_DEPLOYMENT_OR_FULL_ARENA",
        result="PASS" if ok else "FAIL",n06_local_profile_complete=bool(ok),validation_error_type=error,
        source_sha256=before,source_unchanged_during_checks=before==after,python_version=sys.version.split()[0],pytest_counts=counts,
        command_results=results,selection=runs["selection"],validation=runs["validation"],durable_checks=durable,
        timing=timing,timing_matches_real_workload_policy=policy_matches,campaign_authority=authority,
        real_model_timing_measured=bool(timing["real-canary"]),general_public_deployment_complete=False,
        population_p99_certified=False,campaign_independence_established=False,zero_leakage_proven=False,
        n07_recovery_complete=False,full_arena_acceptance=False,guarantee_tier_achieved=None,
        frontend_changed=bool(subprocess.check_output(["git","diff","--name-only","HEAD","--","frontend"],cwd=ROOT)),
        hosted_model_api_used=False,global_ml_packages_changed=False)
    args.output.write_text(json.dumps(receipt,indent=2)+"\n",encoding="ascii",newline="\n")
    print(json.dumps({"result":receipt["result"],"n06_local_profile_complete":bool(ok),"pytest_counts":counts,
        "timing_results":{k:v["result"] if v else None for k,v in timing.items()},"validation_error_type":error}),flush=True)
    return 0 if ok else 1


if __name__=="__main__":raise SystemExit(main())
