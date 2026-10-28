"""Source-bound N06A component tests plus one actual single-lane core regression.

No public execution, calibrated shaping, timing AUC or N06 worker real-model claim.
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
from verify_n04 import sources


ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("lock", "model", "corpus", "corpus-receipt", "corpus-keys", "offline-python", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_RECEIPT_REQUIRED")
    before = sources()
    directory = ROOT / "artifacts/n06-checks" / uuid4().hex
    directory.mkdir(parents=True)
    single = directory / "single-lane-core-regression"
    commands = [("pytest-primary", [sys.executable, "-m", "pytest", "-q", "-W", "error"]),
                ("pytest-offline", [str(args.offline_python.resolve()), "-m", "pytest", "-q", "-W", "error"]),
                ("schemas", [sys.executable, "-m", "arena.cli.main", "schemas", "--output", "contracts/arena.v2.schema.json", "--check"]),
                ("vectors", [sys.executable, "-m", "arena.cli.main", "check-vectors", "--path", "fixtures/arena-v2/vectors.json"]),
                ("control-smoke", [sys.executable, "examples/broker_control_smoke.py"]),
                ("dependencies", [sys.executable, "-m", "pip", "check"]),
                ("single-lane-core-regression", [sys.executable, "-m", "arena.integration.cli", "--lock", str(args.lock.resolve()),
                    "--model", str(args.model.resolve()), "--corpus", str(args.corpus.resolve()),
                    "--corpus-receipt", str(args.corpus_receipt.resolve()), "--corpus-keys", str(args.corpus_keys.resolve()),
                    "--output", str(single), "--traffic", "real", "--mode", "INPUT"])]
    results = []
    for name, command in commands:
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=360)
            code, raw = result.returncode, result.stdout + result.stderr
        except subprocess.TimeoutExpired as error:
            code, raw = 124, (error.stdout or b"") + (error.stderr or b"") + b"\nCOMMAND_TIMEOUT\n"
        log = directory / (name + ".log")
        log.write_bytes(raw)
        labels = raw.decode(errors="replace").strip().splitlines()[-1:]
        label = labels[0] if labels else ""
        if "regression" in name:
            label = "CORE_REGRESSION_PASS" if code == 0 else "CORE_REGRESSION_FAILED"
        results.append({"name": name, "command": command, "exit_code": code, "raw_output": log.relative_to(ROOT.parent).as_posix(),
                        "raw_sha256": sha256(raw), "summary": label})
        print(json.dumps({"name": name, "exit_code": code, "summary": label}), flush=True)
    after = sources()
    real = json.loads((single / "summary.json").read_bytes()) if (single / "summary.json").exists() else None
    counts = [int(found.group(1)) for item in results if item["name"].startswith("pytest")
              for found in [re.search(r"(\d+) passed", item["summary"])] if found]
    receipt = {"schema_version": "arena-n06a-component-verification.v1", "observed_at_utc": datetime.now(timezone.utc).isoformat(),
        "reviewed_base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "scope": "N06A_COMPONENT_SCHEDULER_FOUNDATION_NOT_PUBLIC_OR_CALIBRATED_SHAPING",
        "result": "PASS" if before == after and all(item["exit_code"] == 0 for item in results) and real and real["verifier_exit_code"] == 0 else "FAIL",
        "source_unchanged_during_checks": before == after, "source_sha256": before, "pytest_counts": counts,
        "python_version": sys.version.split()[0], "command_results": results, "core_regression": real,
        "execution_lock_sha256": sha256(args.lock.read_bytes()), "n06_worker_real_model": False,
        "public_execution_available": False, "calibrated_policy": False, "timing_bound_measured": False,
        "full_n06_complete": False, "guarantee_tier_achieved": None,
        "frontend_changed": bool(subprocess.check_output(["git", "diff", "--name-only", "HEAD", "--", "frontend"], cwd=ROOT)),
        "global_ml_packages_changed": False, "hosted_model_api_used": False}
    with args.output.open("x", encoding="ascii", newline="\n") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    return 0 if receipt["result"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
