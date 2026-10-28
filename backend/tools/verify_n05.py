"""Collect source-bound N05 run evidence and execute regression checks.

Run the real three-lane CLI first. This tool rechecks its exact admission/source,
retains its stdout/summary/verifier evidence, runs both isolated test environments
and an actual single-lane regression. It never fabricates a runtime receipt.
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
from arena.contracts.jsonwire import load_wire
from arena.integration.lanes import LaneAdmission
from arena.integration.runtime import runtime_source_hashes
from verify_n04 import sources


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run", "run-log", "lock", "model", "corpus", "corpus-receipt", "corpus-keys", "output", "offline-python"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_RECEIPT_REQUIRED")
    before = sources()
    admission = load_wire(LaneAdmission, args.lock.read_bytes())
    if admission.runtime_source_sha256 != runtime_source_hashes():
        raise ValueError("RUN_ADMISSION_DOES_NOT_MATCH_CURRENT_SOURCE")
    summary = json.loads((args.run / "summary.json").read_bytes())
    if (summary["schema_version"] != "arena-n05-run-receipt.v1" or summary["lane_count"] != 3
        or summary["execution_lock_sha256"] != sha256(args.lock.read_bytes())
        or summary["verifier_exit_code"] != 0 or not summary["real_model"] or summary["run_label"] != "REAL_PUBLIC"
        or summary["turns"] != 6 or not summary["turn_replay_no_redispatch"]
        or any(item["integrity"] != "VALID_WITHIN_PROFILE" for item in summary["results"])):
        raise ValueError("COMPLETE_REAL_THREE_LANE_RUN_REQUIRED")
    if json.loads(args.run_log.read_text(encoding="utf-8-sig").strip()) != summary:
        raise ValueError("RUN_STDOUT_SUMMARY_MISMATCH")
    checks = summary["lane_checks"]
    controls = checks["confinement"]["network_negative_control"]
    baseline = (checks["processing_overlap"]["result"] == "OBSERVED"
                and checks["semantic_recall_result"] == "PASS" and checks["private_history_separation"]
                and all(checks["container_changed_before_reuse"])
                and not checks["cross_lane_markers_observed"] and not checks["post_recreation_markers_observed"]
                and controls["weakened_canary_detected"] and not controls["defended_canary_detected"])
    directory = ROOT / "artifacts/n05-checks" / uuid4().hex
    directory.mkdir(parents=True)
    commands = [("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"]),
                ("pytest-offline", [str(args.offline_python.resolve()), "-m", "pytest", "-q", "-W", "error"]),
                ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
                ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
                ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
                ("contract-smoke", [sys.executable, "examples/monu_contract_smoke.py"]),
                ("dependencies", [sys.executable, "-m", "pip", "check"])]
    single = directory / "single-lane-regression"
    commands.append(("single-lane-real-regression", [sys.executable, "-m", "arena.integration.cli",
        "--lock", str(args.lock.resolve().parent / "cell-admission.json"), "--model", str(args.model.resolve()),
        "--corpus", str(args.corpus.resolve()), "--corpus-receipt", str(args.corpus_receipt.resolve()),
        "--corpus-keys", str(args.corpus_keys.resolve()), "--output", str(single), "--mode", "INPUT", "--traffic", "real"]))
    results = []
    for name, command in commands:
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=360)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as exc:
            code, raw = 124, (exc.stdout or b"") + (exc.stderr or b"") + b"\nCOMMAND_TIMEOUT\n"
        log = directory / (name + ".log")
        log.write_bytes(raw)
        label = raw.decode(errors="replace").strip().splitlines()[-1:]
        if "regression" in name:
            label = ["SINGLE_LANE_RUN_COMPLETE" if code == 0 else "SINGLE_LANE_RUN_FAILED"]
        results.append({"name": name, "command": command, "exit_code": code,
                        "raw_output": log.relative_to(ROOT.parent).as_posix(), "raw_sha256": sha256(raw),
                        "summary": label[0] if label else ""})
        print(json.dumps({"name": name, "exit_code": code, "summary": label}), flush=True)
    after = sources()
    retained = {}
    for label, path in {"n05-summary": args.run / "summary.json", "n05-stdout": args.run_log,
                        "n05-verifier": args.run / "verifier.stdout.json", "n05-admission": args.lock,
                        "cell-admission": args.lock.parent / "cell-admission.json", **{
                        entry["name"]: ROOT.parent / entry["raw_output"] for entry in results}}.items():
        retained[label] = {"path": path.resolve().relative_to(ROOT.parent).as_posix(), "sha256": sha256(path.read_bytes())}
    single_summary = json.loads((single / "summary.json").read_bytes()) if (single / "summary.json").exists() else None
    counts = [int(match.group(1)) for item in results if item["name"].startswith("pytest")
              for match in [re.search(r"(\d+) passed", item["summary"])] if match]
    receipt = {"schema_version": "arena-n05-local-verification.v1", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
               "reviewed_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
               "scope": "N05_LOCAL_THREE_PROCESS_BASELINE_NOT_FULL_ARENA_ACCEPTANCE",
               "result": "PASS" if baseline and before == after and all(row["exit_code"] == 0 for row in results) else "FAIL_OR_INCONCLUSIVE",
               "source_sha256": before, "source_unchanged_during_checks": before == after,
               "consumes_existing_source_locked_real_run": True, "python_version": sys.version.split()[0],
               "pytest_counts": counts, "command_results": results, "retained_outputs": retained,
               "n05_run": summary, "single_lane_regression": single_summary,
               "public_bundle_sha256": sha256((args.run / "public-evidence.zip").read_bytes()),
               "full_probe_acceptance": False, "public_execution_available": False, "guarantee_tier_achieved": None,
               "frontend_changed": bool(subprocess.check_output(["git", "diff", "--name-only", "HEAD", "--", "frontend"], cwd=ROOT)),
               "global_ml_packages_changed": False, "hosted_model_api_used": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="ascii") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    return 0 if receipt["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
