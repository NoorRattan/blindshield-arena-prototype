"""Freeze a finite-workload candidate BEFORE held-out collection. No p99 claim."""

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire
from arena.execution.calibration import select_workload_policy
from arena.execution.policy import FeedbackPolicy, SignedPolicy, disclosure_id, policy_message
from arena.integration.cli import secret_file
from arena.integration.lanes import LaneAdmission
from arena.integration.runtime import runtime_source_hashes

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("execution-lock", "selection-summary", "output"): parser.add_argument("--"+name, type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or not args.output.resolve().is_relative_to(ROOT / "artifacts"):
        raise ValueError("NEW_PRIVATE_PREPARATION_REQUIRED")
    lock = load_wire(LaneAdmission, args.execution_lock.read_bytes())
    if lock.runtime_source_sha256 != runtime_source_hashes(): raise ValueError("CURRENT_RUNTIME_SOURCE_REQUIRED")
    raw = args.selection_summary.read_bytes(); run = json.loads(raw)
    if (run["schema_version"] != "arena-n06-sealed-run.v1" or run["n06_workload"] != "selection"
        or run["execution_lock_sha256"] != sha256(args.execution_lock.read_bytes())
        or run["turns"] != 24 or run["charged_queries"] != 24 or run["authorized_published_jobs"] != 24
        or not run["transport_profile_independently_verified"] or run["verifier_exit_code"] != 0
        or run["verifier_result"]["diagnostics"]["turn_openings_verified"] != 24
        or not run["service_quiesced"] or run["public_execution_available"]):
        raise ValueError("EXACT_SUCCESSFUL_SEALED_SELECTION_REQUIRED")
    policy, metadata = select_workload_policy(run["worker_samples"], FeedbackPolicy.model_validate(run["feedback_policy"]))
    key = Ed25519PrivateKey.generate(); key_id = "n06-local-policy"
    signed = SignedPolicy(policy=policy, signer_key_id=key_id, signature=key.sign(policy_message(policy,key_id)).hex())
    metadata.update(schema_version="arena-n06-workload-selection.v1", selection_summary_sha256=sha256(raw),
        execution_lock_sha256=sha256(args.execution_lock.read_bytes()), policy=policy.model_dump(),
        policy_disclosure_id=disclosure_id(signed), public_admission=False)
    args.output.mkdir(parents=True)
    secret_file(args.output / "policy.key", key.private_bytes_raw())
    (args.output / "policy-public.hex").write_text(key.public_key().public_bytes_raw().hex()+"\n",encoding="ascii")
    (args.output / "policy.json").write_text(signed.model_dump_json(indent=2)+"\n",encoding="ascii")
    (args.output / "preparation.json").write_text(json.dumps(metadata,indent=2)+"\n",encoding="ascii")
    print(json.dumps({"result":"CANDIDATE_FROZEN", "deadline_ms":policy.execution_deadline_ms,"floor_ms":policy.release_floor_ms,"p99_certified":False}))


if __name__ == "__main__": main()
